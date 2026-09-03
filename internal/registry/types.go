// Package registry holds the sealed nym registry for nymserv-ng.
//
// The registry is the only long-lived secret state on the host. It is stored
// as a single blob encrypted with XChaCha20-Poly1305 under a key derived from
// an operator passphrase with Argon2id. The passphrase is supplied over the
// control socket after every restart and is never written to the host.
//
// Two properties in this package are load-bearing for the threat model and
// must not be relaxed without revisiting the design document:
//
//   - The hSub key ratchets forward on every use and the previous value is
//     overwritten in place. Seizure of a running host therefore cannot compute
//     any tag issued before the seizure, so a nym's past posts to the shared
//     mailbox stay unlinkable.
//   - One-time prekeys are removed from the pool when consumed. The server
//     never held the private halves, so it cannot decrypt earlier messages.
package registry

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Mode records which protocol a nym speaks. Legacy nyms are OpenPGP clients
// inherited from Zax-style nymserv; they get a strictly weaker service and are
// expected to migrate.
type Mode uint8

const (
	ModeModern Mode = 1
	ModeLegacy Mode = 2
)

func (m Mode) String() string {
	switch m {
	case ModeModern:
		return "modern"
	case ModeLegacy:
		return "legacy"
	default:
		return "invalid"
	}
}

// Flags is a bitfield of per-nym state.
type Flags uint32

const (
	// FlagDisabled suppresses all delivery for this alias.
	FlagDisabled Flags = 1 << iota
	// FlagNoLimit exempts the alias from the daily message ceiling.
	FlagNoLimit
	// FlagNoForwardSecrecy is set on legacy nyms and on modern nyms that have
	// exhausted their one-time prekey pool and fallen back to the
	// medium-term prekey.
	FlagNoForwardSecrecy
)

func (f Flags) Has(x Flags) bool { return f&x != 0 }

const (
	// KeyLen is the length of every raw key stored in the registry: Ed25519
	// public keys, X25519 public keys and hSub ratchet keys are all 32 bytes.
	KeyLen = 32

	// PrekeyLowWater is the pool size below which nymservd asks the owner to
	// top up. The request rides on the next scheduled outbound message; it is
	// never sent out of band, because an out-of-band notice is itself a
	// traffic signal.
	PrekeyLowWater = 16

	// PrekeyPoolMax caps how many one-time prekeys a nym may hold, bounding
	// both memory and the damage from a flooding client.
	PrekeyPoolMax = 512

	// hsubRatchetInfo is the domain separator for the hSub key ratchet. It is
	// part of the wire protocol: changing it desynchronises every client.
	hsubRatchetInfo = "nymserv-ng/hsub-ratchet/v1"
)

var (
	ErrPrekeyPoolEmpty = errors.New("registry: one-time prekey pool is empty")
	ErrPrekeyPoolFull  = errors.New("registry: one-time prekey pool is full")
	ErrWrongMode       = errors.New("registry: operation not valid for this nym mode")
)

// Prekey is a single one-time X25519 public key uploaded by the nym owner.
// The server never sees the private half.
type Prekey struct {
	ID  uint64       `json:"id"`
	Pub [KeyLen]byte `json:"pub"`
}

// Nym is one registered pseudonym.
//
// Field visibility note: everything here is either public key material or
// server-side bookkeeping. No plaintext message content and no correspondent
// addresses are ever stored.
type Nym struct {
	Alias string `json:"alias"`
	Mode  Mode   `json:"mode"`
	Flags Flags  `json:"flags"`

	// --- modern mode ---

	// IdentityKey is the nym's Ed25519 public key. Inbound envelopes are
	// verified against it.
	IdentityKey [KeyLen]byte `json:"identity_key,omitempty"`

	// Counter is the highest envelope counter accepted so far. Inbound
	// messages must carry a strictly greater value. This is the primary
	// replay defence for modern nyms; the digest cache is the backstop.
	Counter uint64 `json:"counter"`

	// Prekeys is the remaining one-time prekey pool, consumed from the front.
	Prekeys []Prekey `json:"prekeys,omitempty"`

	// MediumTermPrekey is the signed fallback used when the pool is empty.
	// Messages encrypted to it are not forward-secret and are marked as such
	// in the envelope so the client can warn.
	MediumTermPrekey [KeyLen]byte `json:"medium_term_prekey,omitempty"`

	// --- hSub ratchet (modern only) ---

	// HsubKey is K_n: the key used to derive the *next* subject tag. It is
	// overwritten by ConsumeHsubKey and the previous value is not recoverable
	// from what remains on the host.
	HsubKey [KeyLen]byte `json:"hsub_key,omitempty"`

	// HsubEpoch is n, the ratchet index. It travels in the payload so the
	// client can resynchronise after lost posts.
	HsubEpoch uint32 `json:"hsub_epoch"`

	// --- legacy mode ---

	// PGPPublicKey is the validated OpenPGP key material for legacy nyms,
	// stored as parsed packet bytes. nymservd never shells out to gpg and
	// never touches a GnuPG keyring.
	PGPPublicKey []byte `json:"pgp_public_key,omitempty"`

	// PGPFingerprint identifies the key above.
	PGPFingerprint []byte `json:"pgp_fingerprint,omitempty"`

	// LegacySubjectKey is the static hSub key for legacy nyms. It does not
	// ratchet, so seizure links the alias to every past post. This is
	// unavoidable in legacy mode and is the strongest argument for the
	// deprecation window.
	LegacySubjectKey [KeyLen]byte `json:"legacy_subject_key,omitempty"`

	// --- accounting ---

	// CreatedDay and LastActiveDay are days since the Unix epoch. Day
	// granularity is deliberate: finer timestamps are metadata.
	CreatedDay    uint32 `json:"created_day"`
	LastActiveDay uint32 `json:"last_active_day"`

	// DayIndex is the day the counter below applies to; DayCount is the
	// number of messages handled that day.
	DayIndex uint32 `json:"day_index"`
	DayCount uint32 `json:"day_count"`
}

// Today returns the current day number since the Unix epoch, in UTC.
func Today() uint32 {
	return uint32(time.Now().UTC().Unix() / 86400)
}

// ConsumeHsubKey returns the current ratchet key and epoch, then advances the
// ratchet in place:
//
//	K_{n+1} = BLAKE2b-256(K_n || hsubRatchetInfo)
//
// The returned key is a copy; the caller must zero it after deriving the tag.
// After this call the stored K_n is gone.
//
// Legacy nyms have no ratchet and must use LegacySubjectKey instead.
func (n *Nym) ConsumeHsubKey() (key [KeyLen]byte, epoch uint32, err error) {
	if n.Mode != ModeModern {
		return key, 0, ErrWrongMode
	}

	key = n.HsubKey
	epoch = n.HsubEpoch

	h, err := blake2b.New256(nil)
	if err != nil {
		return [KeyLen]byte{}, 0, fmt.Errorf("registry: blake2b: %w", err)
	}
	h.Write(n.HsubKey[:])
	h.Write([]byte(hsubRatchetInfo))
	sum := h.Sum(nil)

	copy(n.HsubKey[:], sum)
	wipe(sum)
	n.HsubEpoch++

	return key, epoch, nil
}

// ConsumePrekey removes and returns the oldest unused one-time prekey.
//
// On ErrPrekeyPoolEmpty the caller falls back to MediumTermPrekey and sets
// FlagNoForwardSecrecy for that message. Callers must only reach this point
// for messages that have already passed every authentication check: burning
// prekeys on unauthenticated input is a denial-of-service vector.
func (n *Nym) ConsumePrekey() (Prekey, error) {
	if n.Mode != ModeModern {
		return Prekey{}, ErrWrongMode
	}
	if len(n.Prekeys) == 0 {
		return Prekey{}, ErrPrekeyPoolEmpty
	}

	pk := n.Prekeys[0]

	// Shift down and clear the vacated tail slot so the consumed key does not
	// linger in the backing array.
	copy(n.Prekeys, n.Prekeys[1:])
	n.Prekeys[len(n.Prekeys)-1] = Prekey{}
	n.Prekeys = n.Prekeys[:len(n.Prekeys)-1]

	return pk, nil
}

// AddPrekeys appends uploaded one-time prekeys, rejecting the batch if it
// would exceed PrekeyPoolMax.
func (n *Nym) AddPrekeys(pks []Prekey) error {
	if n.Mode != ModeModern {
		return ErrWrongMode
	}
	if len(n.Prekeys)+len(pks) > PrekeyPoolMax {
		return ErrPrekeyPoolFull
	}
	n.Prekeys = append(n.Prekeys, pks...)
	return nil
}

// NeedsPrekeyTopUp reports whether the pool has fallen below the low-water
// mark. The result must only influence content that rides on an
// already-scheduled outbound message, never the schedule itself.
func (n *Nym) NeedsPrekeyTopUp() bool {
	return n.Mode == ModeModern && len(n.Prekeys) < PrekeyLowWater
}

// BumpCounter records one handled message for the current day and reports the
// running total. The day counter resets on a new day.
func (n *Nym) BumpCounter(day uint32) uint32 {
	if n.DayIndex != day {
		n.DayIndex = day
		n.DayCount = 0
	}
	n.DayCount++
	n.LastActiveDay = day
	return n.DayCount
}

// nowUnix is a seam for tests; production always uses the wall clock.
var nowUnix = func() int64 { return time.Now().Unix() }
