package registry

import (
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func acceptStore(t *testing.T) (*Store, *Nym) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "pw"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	n := newNym(t, "alice")
	if err := s.Add(n); err != nil {
		t.Fatal(err)
	}
	return s, n
}

func digest(t *testing.T) [32]byte {
	t.Helper()
	var d [32]byte
	if _, err := rand.Read(d[:]); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAcceptHappyPath(t *testing.T) {
	s, n := acceptStore(t)
	defer s.Close()

	alias, err := s.Accept(n.IdentityKey, 1, digest(t))
	if err != nil {
		t.Fatal(err)
	}
	if alias != "alice" {
		t.Fatalf("wrong alias: %s", alias)
	}

	got, _ := s.Get("alice")
	if got.Counter != 1 {
		t.Fatalf("counter not persisted: %d", got.Counter)
	}
	if got.DayCount != 1 {
		t.Fatalf("day count not persisted: %d", got.DayCount)
	}
}

func TestAcceptUnknownIdentity(t *testing.T) {
	s, _ := acceptStore(t)
	defer s.Close()

	var unknown [KeyLen]byte
	if _, err := rand.Read(unknown[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(unknown, 1, digest(t)); !errors.Is(err, ErrNoSuchNym) {
		t.Fatalf("want ErrNoSuchNym, got %v", err)
	}
}

func TestAcceptCounterMustAdvance(t *testing.T) {
	s, n := acceptStore(t)
	defer s.Close()

	if _, err := s.Accept(n.IdentityKey, 5, digest(t)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []uint64{0, 1, 5} {
		if _, err := s.Accept(n.IdentityKey, c, digest(t)); !errors.Is(err, ErrCounterNotMonotonic) {
			t.Fatalf("counter %d: want ErrCounterNotMonotonic, got %v", c, err)
		}
	}
	if _, err := s.Accept(n.IdentityKey, 6, digest(t)); err != nil {
		t.Fatalf("counter 6 should be accepted: %v", err)
	}
}

// TestAcceptRejectsReplay covers the backstop behind the counter: the same
// envelope re-injected verbatim.
func TestAcceptRejectsReplay(t *testing.T) {
	s, n := acceptStore(t)
	defer s.Close()

	d := digest(t)
	if _, err := s.Accept(n.IdentityKey, 1, d); err != nil {
		t.Fatal(err)
	}
	// A higher counter with the same digest is still a replay of the same
	// ciphertext and must be refused.
	if _, err := s.Accept(n.IdentityKey, 2, d); !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
}

func TestAcceptDisabledAlias(t *testing.T) {
	s, n := acceptStore(t)
	defer s.Close()

	if err := s.Update(func(nyms map[string]*Nym) error {
		nyms["alice"].Flags |= FlagDisabled
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(n.IdentityKey, 1, digest(t)); !errors.Is(err, ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
}

func TestAcceptRateLimit(t *testing.T) {
	s, n := acceptStore(t)
	defer s.Close()

	if err := s.Update(func(nyms map[string]*Nym) error {
		nyms["alice"].DayIndex = Today()
		nyms["alice"].DayCount = DefaultDailyLimit
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Accept(n.IdentityKey, 1, digest(t)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}

	// A rate-limited message must not have consumed the counter slot, or a
	// burst of refused messages would lock the alias out afterwards.
	got, _ := s.Get("alice")
	if got.Counter != 0 {
		t.Fatalf("rate-limited message advanced the counter to %d", got.Counter)
	}
}

// TestAcceptIsAtomicUnderConcurrency is the regression test for the TOCTOU in
// the original implementation, which read the counter back after releasing the
// lock and so let concurrent deliveries interleave past the ceiling.
func TestAcceptIsAtomicUnderConcurrency(t *testing.T) {
	s, n := acceptStore(t)
	defer s.Close()

	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0

	// Every worker submits the same counter value. Exactly one may win.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Accept(n.IdentityKey, 1, digest(t)); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("exactly one delivery should win the counter, got %d", accepted)
	}
}

func TestAcceptOnSealedStore(t *testing.T) {
	s, n := acceptStore(t)
	s.Close()

	if _, err := s.Accept(n.IdentityKey, 1, digest(t)); !errors.Is(err, ErrSealed) {
		t.Fatalf("want ErrSealed, got %v", err)
	}
}
