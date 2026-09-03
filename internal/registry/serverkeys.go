package registry

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Server key state, per §2.4 of the design document.
//
// The identity key is Ed25519 and lives on an offline machine. Only its public
// half is stored here, pinned: nymservd can verify a bundle but can never
// produce one, so compromise of the running host does not let an attacker
// impersonate the server to clients.
//
// Encryption keys are X25519 and rotate on a fixed schedule. The previous
// epoch's private key is retained for the whole overlap window; dropping it
// early silently breaks every client that has not yet refetched the bundle.

const (
	// EpochDays is the lifetime of one encryption key.
	EpochDays = 90
	// OverlapDays is how long the previous key stays acceptable after
	// rotation.
	OverlapDays = 30
)

var (
	ErrNoIdentity  = errors.New("registry: no server identity key pinned")
	ErrNoServerKey = errors.New("registry: no server encryption key")
	ErrIdentitySet = errors.New("registry: identity key already pinned")
)

// KeyEpoch is one X25519 encryption key and its validity window.
type KeyEpoch struct {
	Priv  [KeyLen]byte `json:"priv"`
	Pub   [KeyLen]byte `json:"pub"`
	From  uint32       `json:"from"`  // day number, inclusive
	Until uint32       `json:"until"` // day number, exclusive
}

// ServerState is the server's own key material.
type ServerState struct {
	// IdentityPub is the pinned Ed25519 public key. Set once; changing it is a
	// deliberate out-of-band event, not something the daemon can do.
	IdentityPub []byte `json:"identity_pub"`

	Current  *KeyEpoch `json:"current,omitempty"`
	Previous *KeyEpoch `json:"previous,omitempty"`

	// Bundle is the signed key bundle published to clients. It is produced
	// offline by the keytool and imported here; the daemon stores and serves
	// it but cannot create it.
	Bundle []byte `json:"bundle,omitempty"`
}

// SetIdentity pins the server identity public key. It refuses to overwrite an
// existing pin, because silently replacing it would be exactly the move a
// compromised host would want to make.
func (s *Store) SetIdentity(pub []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return ErrSealed
	}
	if s.c.Server == nil {
		s.c.Server = &ServerState{}
	}
	if len(s.c.Server.IdentityPub) != 0 {
		return ErrIdentitySet
	}
	s.c.Server.IdentityPub = append([]byte(nil), pub...)
	return s.save()
}

// Identity returns the pinned identity public key.
func (s *Store) Identity() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return nil, ErrSealed
	}
	if s.c.Server == nil || len(s.c.Server.IdentityPub) == 0 {
		return nil, ErrNoIdentity
	}
	return append([]byte(nil), s.c.Server.IdentityPub...), nil
}

// RotateKey generates a fresh encryption epoch, demoting the current key to
// previous. It returns the new public key so the operator can take it to the
// offline machine and sign a bundle for it.
//
// Rotation is explicit, not automatic on a timer: signing the resulting bundle
// requires the offline identity key, so an unattended rotation would produce a
// key that clients have no way to trust.
func (s *Store) RotateKey(today uint32) (KeyEpoch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return KeyEpoch{}, ErrSealed
	}
	if s.c.Server == nil {
		s.c.Server = &ServerState{}
	}

	var priv [KeyLen]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyEpoch{}, fmt.Errorf("registry: generate key: %w", err)
	}
	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyEpoch{}, fmt.Errorf("registry: derive public: %w", err)
	}

	next := &KeyEpoch{From: today, Until: today + EpochDays}
	copy(next.Priv[:], priv[:])
	copy(next.Pub[:], pubSlice)

	// Keep the outgoing key only for the overlap window. Anything older is
	// dropped: retaining a key past its usefulness only widens what a seizure
	// can decrypt.
	if cur := s.c.Server.Current; cur != nil {
		cur.Until = today + OverlapDays
		s.c.Server.Previous = cur
	}
	s.c.Server.Current = next
	s.c.Server.Bundle = nil // the old bundle no longer describes the current key

	if err := s.save(); err != nil {
		return KeyEpoch{}, err
	}
	return *next, nil
}

// ServerEncryptionKeys returns the private keys nymservd should try, current
// first, dropping the previous key once its overlap has expired.
func (s *Store) ServerEncryptionKeys(today uint32) (cur [KeyLen]byte, prev [KeyLen]byte, hasPrev bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return cur, prev, false, ErrSealed
	}
	if s.c.Server == nil || s.c.Server.Current == nil {
		return cur, prev, false, ErrNoServerKey
	}

	cur = s.c.Server.Current.Priv
	if p := s.c.Server.Previous; p != nil && today < p.Until {
		prev = p.Priv
		hasPrev = true
	}
	return cur, prev, hasPrev, nil
}

// CurrentPublic returns the current encryption public key and its window.
func (s *Store) CurrentPublic() (KeyEpoch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return KeyEpoch{}, ErrSealed
	}
	if s.c.Server == nil || s.c.Server.Current == nil {
		return KeyEpoch{}, ErrNoServerKey
	}
	e := *s.c.Server.Current
	e.Priv = [KeyLen]byte{} // never hand the private half outside the store
	return e, nil
}

// SetBundle stores a signed key bundle. The caller must have verified it
// against the pinned identity key first.
func (s *Store) SetBundle(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return ErrSealed
	}
	if s.c.Server == nil {
		return ErrNoServerKey
	}
	s.c.Server.Bundle = append([]byte(nil), b...)
	return s.save()
}

// Bundle returns the stored signed key bundle, if any.
func (s *Store) Bundle() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return nil, ErrSealed
	}
	if s.c.Server == nil || len(s.c.Server.Bundle) == 0 {
		return nil, ErrNoServerKey
	}
	return append([]byte(nil), s.c.Server.Bundle...), nil
}
