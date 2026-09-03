package registry

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

var (
	ErrSealed      = errors.New("registry: store is sealed")
	ErrAlreadyOpen = errors.New("registry: store is already unsealed")
	ErrNoSuchNym   = errors.New("registry: no such nym")
	ErrNymExists   = errors.New("registry: nym already exists")
	ErrExists      = errors.New("registry: registry file already exists")
)

// ReplayTTL is how long a message digest stays in the replay cache. It matches
// the design document: long enough that a captured message cannot be usefully
// re-injected, short enough that the cache does not grow without bound.
const ReplayTTL = 30 * 24 * time.Hour

// contents is the JSON-serialised plaintext of the sealed blob.
//
// The whole registry is one blob, rewritten in full on every change. At the
// scale this server operates (hundreds of nyms, not millions) the cost is
// irrelevant and the failure modes are far simpler than per-record sealing:
// there is no way to end up with a half-written store. The types are shaped so
// that moving to individually sealed records later stays internal to this
// package.
type contents struct {
	Nyms   map[string]*Nym  `json:"nyms"`
	Replay map[string]int64 `json:"replay"` // digest (base64) -> unix expiry
	Server *ServerState     `json:"server,omitempty"`
}

// Store owns the sealed registry.
//
// A Store starts sealed. nymservd binds its ingest socket and pools incoming
// messages while sealed, but processes nothing until the operator supplies the
// passphrase over the control socket.
type Store struct {
	mu sync.RWMutex

	path   string
	params KDFParams

	// key is the derived sealing key, held in locked memory for the process
	// lifetime. This is the one place memguard genuinely earns its keep.
	key *memguard.LockedBuffer

	// salt is retained so that saves reuse the same KDF work. The nonce is
	// freshly generated on every save.
	salt []byte

	c *contents
}

// Create initialises a new sealed registry at path. It fails if the file
// already exists, so it can never silently destroy an existing store.
//
// The passphrase buffer belongs to the caller.
func Create(path string, passphrase *memguard.LockedBuffer, params KDFParams) (*Store, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("registry: stat: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("registry: salt: %w", err)
	}

	key, err := deriveKey(passphrase, salt, params)
	if err != nil {
		return nil, err
	}

	s := &Store{
		path:   path,
		params: params,
		key:    key,
		salt:   salt,
		c: &contents{
			Nyms:   make(map[string]*Nym),
			Replay: make(map[string]int64),
		},
	}

	if err := s.save(); err != nil {
		key.Destroy()
		return nil, err
	}
	return s, nil
}

// Open reads the registry file and returns a sealed Store. Nothing is
// decrypted here; call Unseal to make it usable.
func Open(path string) (*Store, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read: %w", err)
	}
	params, salt, _, err := parseHeader(blob)
	if err != nil {
		return nil, err
	}

	saltCopy := make([]byte, saltLen)
	copy(saltCopy, salt)

	return &Store{path: path, params: params, salt: saltCopy}, nil
}

// Unseal derives the key and decrypts the registry into memory.
//
// The passphrase buffer belongs to the caller and is not destroyed here; the
// caller should destroy it as soon as this returns, in either outcome.
func (s *Store) Unseal(passphrase *memguard.LockedBuffer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c != nil {
		return ErrAlreadyOpen
	}

	blob, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("registry: read: %w", err)
	}

	plaintext, key, params, err := unseal(blob, passphrase)
	if err != nil {
		return err
	}
	defer wipe(plaintext)

	var c contents
	if err := json.Unmarshal(plaintext, &c); err != nil {
		key.Destroy()
		return fmt.Errorf("registry: parse: %w", err)
	}
	if c.Nyms == nil {
		c.Nyms = make(map[string]*Nym)
	}
	if c.Replay == nil {
		c.Replay = make(map[string]int64)
	}

	s.key = key
	s.params = params
	s.c = &c
	return nil
}

// IsSealed reports whether the store still needs a passphrase.
func (s *Store) IsSealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c == nil
}

// Close wipes the in-memory registry and destroys the sealing key. The store
// returns to the sealed state.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.key != nil {
		s.key.Destroy()
		s.key = nil
	}
	if s.c != nil {
		for _, n := range s.c.Nyms {
			wipe(n.HsubKey[:])
			wipe(n.LegacySubjectKey[:])
		}
		s.c = nil
	}
}

// save writes the current contents atomically. Callers must hold s.mu.
//
// Note on residue: the previous ciphertext remains recoverable on a journalled
// or copy-on-write filesystem. That is acceptable because it is ciphertext
// under the same key, but it does mean an adversary holding the key can
// reconstruct earlier registry states, including hSub keys already ratcheted
// past. Placing the registry on a full-disk-encrypted volume is what bounds
// this; in-place overwriting would not.
func (s *Store) save() error {
	if s.c == nil || s.key == nil {
		return ErrSealed
	}

	plaintext, err := json.Marshal(s.c)
	if err != nil {
		return fmt.Errorf("registry: marshal: %w", err)
	}

	blob, err := seal(plaintext, s.key, s.params, s.salt) // seal wipes plaintext
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".registry-*")
	if err != nil {
		return fmt.Errorf("registry: temp: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("registry: chmod: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return fmt.Errorf("registry: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("registry: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("registry: close: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("registry: rename: %w", err)
	}

	// fsync the directory so the rename itself is durable.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Save flushes the registry to disk.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}

// Update runs fn against the live registry under the write lock and persists
// the result. If fn returns an error nothing is written, so a failed mutation
// cannot leave a partially applied state on disk.
//
// Every state change that matters -- ratchet advance, prekey consumption,
// counter bump -- must go through here, because each of them is only safe if
// it is durable before the resulting message is released.
func (s *Store) Update(fn func(nyms map[string]*Nym) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return ErrSealed
	}
	if err := fn(s.c.Nyms); err != nil {
		return err
	}
	return s.save()
}

// View runs fn against a read-only view of the registry.
//
// fn must not retain pointers beyond the call and must not mutate what it is
// given; use Update for anything that changes state.
func (s *Store) View(fn func(nyms map[string]*Nym) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return ErrSealed
	}
	return fn(s.c.Nyms)
}

// Add registers a new nym.
func (s *Store) Add(n *Nym) error {
	return s.Update(func(nyms map[string]*Nym) error {
		if _, ok := nyms[n.Alias]; ok {
			return ErrNymExists
		}
		if n.CreatedDay == 0 {
			n.CreatedDay = Today()
		}
		n.LastActiveDay = n.CreatedDay
		nyms[n.Alias] = n
		return nil
	})
}

// Remove deletes a nym and wipes its key material.
func (s *Store) Remove(alias string) error {
	return s.Update(func(nyms map[string]*Nym) error {
		n, ok := nyms[alias]
		if !ok {
			return ErrNoSuchNym
		}
		wipe(n.HsubKey[:])
		wipe(n.LegacySubjectKey[:])
		delete(nyms, alias)
		return nil
	})
}

// Get returns a copy of a nym record. A copy, not a pointer: callers outside
// this package must not be able to mutate registry state without going through
// Update, or a ratchet advance could be lost.
func (s *Store) Get(alias string) (Nym, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return Nym{}, ErrSealed
	}
	n, ok := s.c.Nyms[alias]
	if !ok {
		return Nym{}, ErrNoSuchNym
	}
	cp := *n
	cp.Prekeys = append([]Prekey(nil), n.Prekeys...)
	cp.PGPPublicKey = append([]byte(nil), n.PGPPublicKey...)
	cp.PGPFingerprint = append([]byte(nil), n.PGPFingerprint...)
	return cp, nil
}

// Aliases lists the registered aliases.
//
// This exists for administration only. It must never be exposed over the mail
// or network interface: the enumeration commands in the original nymserv
// (`list`, `used`, and the finger daemon) are exactly the anonymity leak this
// implementation removes.
func (s *Store) Aliases() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return nil, ErrSealed
	}
	out := make([]string, 0, len(s.c.Nyms))
	for a := range s.c.Nyms {
		out = append(out, a)
	}
	return out, nil
}

// SeenBefore reports whether digest is already in the replay cache and, if
// not, records it. It returns true when the message must be dropped.
//
// The digest is expected to be BLAKE2b-256 over the envelope's ephemeral
// public key and nonce (modern mode) or over the whole ciphertext (legacy
// mode, which carries no counter).
func (s *Store) SeenBefore(digest string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return true, ErrSealed
	}

	now := time.Now().Unix()
	if exp, ok := s.c.Replay[digest]; ok && exp > now {
		return true, nil
	}

	s.c.Replay[digest] = now + int64(ReplayTTL/time.Second)
	return false, s.save()
}

// ExpireReplay drops replay entries past their TTL and reports how many were
// removed. Run it on a fixed schedule, never in response to traffic.
func (s *Store) ExpireReplay() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c == nil {
		return 0, ErrSealed
	}

	now := time.Now().Unix()
	removed := 0
	for d, exp := range s.c.Replay {
		if exp <= now {
			delete(s.c.Replay, d)
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, s.save()
}
