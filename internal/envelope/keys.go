package envelope

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

// Server key hierarchy.
//
// The identity key is Ed25519 and its private half never exists on the server.
// It signs encryption-key bundles offline. Compromise of a running host
// therefore lets an attacker read mail but not impersonate the server to
// clients, which is the property that makes rotation safe to automate.
//
// Encryption keys are X25519 and rotate every 90 days with a 30-day overlap
// during which both the current and previous key are accepted. Without the
// overlap, a client that sent just before a rotation would produce ciphertext
// nobody could open.

const (
	// KeyIDLen is the length of the truncated key identifier carried in every
	// envelope so the server knows which private key to try. It is a lookup
	// hint, not a secret and not an authenticator.
	KeyIDLen = 8

	bundleMagic = "NYMSNGK1"

	// bundleLen is magic(8) + valid_from(4) + valid_until(4) + enc_pk(32) +
	// prev_pk(32) + sig(64).
	bundleSignedLen = 8 + 4 + 4 + 32 + 32
	bundleLen       = bundleSignedLen + ed25519.SignatureSize

	// EpochDays mirrors the registry constant; both sides must agree.
	EpochDays = registryEpochDays
	// OverlapDays is how long the previous key stays acceptable.
	OverlapDays = registryOverlapDays
)

var (
	ErrBadBundle       = errors.New("envelope: malformed key bundle")
	ErrBundleSignature = errors.New("envelope: key bundle signature is invalid")
	ErrBundleExpired   = errors.New("envelope: key bundle has expired")
	ErrWrongIdentity   = errors.New("envelope: bundle signed by an unexpected identity key")
)

// KeyID derives the envelope key identifier for an X25519 public key.
func KeyID(pub *[32]byte) [KeyIDLen]byte {
	sum := blake2b.Sum256(pub[:])
	var id [KeyIDLen]byte
	copy(id[:], sum[:KeyIDLen])
	return id
}

// Bundle is the signed statement binding an encryption key to a validity
// window. Clients fetch it over onion HTTPS, or recover it from the shared
// mailbox if that path is unavailable.
type Bundle struct {
	ValidFrom  uint32 // day number since the Unix epoch
	ValidUntil uint32
	EncPub     [32]byte
	PrevPub    [32]byte // all zero when there is no predecessor
	Signature  [ed25519.SignatureSize]byte
}

// Marshal serialises the bundle in its canonical wire form.
func (b *Bundle) Marshal() []byte {
	out := make([]byte, bundleLen)
	copy(out[0:], bundleMagic)
	binary.BigEndian.PutUint32(out[8:], b.ValidFrom)
	binary.BigEndian.PutUint32(out[12:], b.ValidUntil)
	copy(out[16:], b.EncPub[:])
	copy(out[48:], b.PrevPub[:])
	copy(out[bundleSignedLen:], b.Signature[:])
	return out
}

// Sign fills in the signature. This runs on the offline machine that holds the
// identity private key; it is never called by nymservd.
func (b *Bundle) Sign(identityPriv ed25519.PrivateKey) {
	raw := b.Marshal()
	sig := ed25519.Sign(identityPriv, raw[:bundleSignedLen])
	copy(b.Signature[:], sig)
}

// ParseBundle validates a bundle against a pinned identity key and a current
// day number.
//
// Clients pin the identity key on first use and must refuse any bundle signed
// by a different one: changing identity is a deliberate out-of-band event
// verified by fingerprint, not something a compromised host can do quietly.
func ParseBundle(raw []byte, identityPub ed25519.PublicKey, today uint32) (*Bundle, error) {
	if len(raw) != bundleLen {
		return nil, ErrBadBundle
	}
	if string(raw[:8]) != bundleMagic {
		return nil, ErrBadBundle
	}
	if len(identityPub) != ed25519.PublicKeySize {
		return nil, ErrWrongIdentity
	}
	if !ed25519.Verify(identityPub, raw[:bundleSignedLen], raw[bundleSignedLen:]) {
		return nil, ErrBundleSignature
	}

	b := &Bundle{
		ValidFrom:  binary.BigEndian.Uint32(raw[8:]),
		ValidUntil: binary.BigEndian.Uint32(raw[12:]),
	}
	copy(b.EncPub[:], raw[16:48])
	copy(b.PrevPub[:], raw[48:80])
	copy(b.Signature[:], raw[bundleSignedLen:])

	if b.ValidUntil <= b.ValidFrom {
		return nil, ErrBadBundle
	}
	if today >= b.ValidUntil {
		return nil, ErrBundleExpired
	}
	return b, nil
}

// ServerKeys is the set of private keys nymservd will attempt, current first.
//
// Holding the previous key is what implements the rotation overlap. Dropping
// it early silently breaks clients that have not yet refetched the bundle.
type ServerKeys struct {
	Current  [32]byte // X25519 private
	Previous [32]byte // X25519 private, or all zero
	HasPrev  bool
}

// publicOf derives the X25519 public key for a private key.
func publicOf(priv *[32]byte) ([32]byte, error) {
	var pub [32]byte
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("envelope: derive public key: %w", err)
	}
	copy(pub[:], out)
	return pub, nil
}

// selectKey returns the private key matching the envelope's key_id.
//
// The comparison is on a non-secret lookup hint, so a plain equality check is
// correct here. Nothing about which key matched is ever revealed to the sender:
// a miss takes the same uniform failure path as a bad tag or a bad signature.
func (sk *ServerKeys) selectKey(id [KeyIDLen]byte) (*[32]byte, bool) {
	cur, err := publicOf(&sk.Current)
	if err == nil && KeyID(&cur) == id {
		return &sk.Current, true
	}
	if sk.HasPrev {
		prev, err := publicOf(&sk.Previous)
		if err == nil && KeyID(&prev) == id {
			return &sk.Previous, true
		}
	}
	return nil, false
}

// The epoch constants are duplicated here rather than imported so that this
// package stays free of any dependency on the registry. They must match.
const (
	registryEpochDays   = 90
	registryOverlapDays = 30
)
