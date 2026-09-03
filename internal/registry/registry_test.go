package registry

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/blake2b"
)

// testKDFParams keeps the tests fast. Production uses DefaultKDFParams.
var testKDFParams = KDFParams{Time: 1, MemoryKiB: 32 * 1024, Parallelism: 1}

func pass(t *testing.T, s string) *memguard.LockedBuffer {
	t.Helper()
	return memguard.NewBufferFromBytes([]byte(s))
}

func newNym(t *testing.T, alias string) *Nym {
	t.Helper()
	n := &Nym{Alias: alias, Mode: ModeModern, CreatedDay: Today()}
	if _, err := rand.Read(n.IdentityKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(n.HsubKey[:]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCreateUnsealRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")

	s, err := Create(path, pass(t, "correct horse"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	n := newNym(t, "alice")
	want := n.IdentityKey
	if err := s.Add(n); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.IsSealed() {
		t.Fatal("store should start sealed")
	}
	if _, err := s2.Get("alice"); !errors.Is(err, ErrSealed) {
		t.Fatalf("sealed store should refuse reads, got %v", err)
	}
	if err := s2.Unseal(pass(t, "correct horse")); err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.IdentityKey != want {
		t.Fatal("identity key did not survive the round trip")
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "right"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, _ := Open(path)
	if err := s2.Unseal(pass(t, "wrong")); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("want ErrUnsealFailed, got %v", err)
	}
	if !s2.IsSealed() {
		t.Fatal("store must remain sealed after a failed unseal")
	}
}

func TestTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "pw"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newNym(t, "bob")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-20] ^= 0x01
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	s2, _ := Open(path)
	if err := s2.Unseal(pass(t, "pw")); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("tampered ciphertext must fail to open, got %v", err)
	}
}

// TestKDFDowngradeRejected checks that rewriting the header to a trivially
// cheap Argon2 cost is refused rather than honoured.
func TestKDFDowngradeRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "pw"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	blob, _ := os.ReadFile(path)
	blob[offMemory] = 0
	blob[offMemory+1] = 0
	blob[offMemory+2] = 0
	blob[offMemory+3] = 1 // 1 KiB
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); !errors.Is(err, ErrWeakKDFParams) {
		t.Fatalf("want ErrWeakKDFParams, got %v", err)
	}
}

// TestHsubRatchetIsForwardOnly is the important one: after consuming a key the
// stored state must not allow recomputing it.
func TestHsubRatchetIsForwardOnly(t *testing.T) {
	n := newNym(t, "carol")
	initial := n.HsubKey

	k0, e0, err := n.ConsumeHsubKey()
	if err != nil {
		t.Fatal(err)
	}
	if k0 != initial || e0 != 0 {
		t.Fatal("first consume must return the initial key at epoch 0")
	}
	if n.HsubKey == initial {
		t.Fatal("ratchet did not advance")
	}
	if n.HsubEpoch != 1 {
		t.Fatalf("epoch should be 1, got %d", n.HsubEpoch)
	}

	// The stored key must be exactly the defined forward step, and there must
	// be no way back: BLAKE2b is preimage resistant, so demonstrating the
	// forward relation is the strongest statement a unit test can make.
	h, _ := blake2b.New256(nil)
	h.Write(k0[:])
	h.Write([]byte(hsubRatchetInfo))
	if !bytes.Equal(h.Sum(nil), n.HsubKey[:]) {
		t.Fatal("ratchet step does not match the specified derivation")
	}

	k1, e1, _ := n.ConsumeHsubKey()
	if k1 == k0 {
		t.Fatal("consecutive consumes returned the same key")
	}
	if e1 != 1 {
		t.Fatalf("second epoch should be 1, got %d", e1)
	}
}

func TestRatchetPersistsAcrossSeal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "pw"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newNym(t, "dave")); err != nil {
		t.Fatal(err)
	}

	var consumed [KeyLen]byte
	err = s.Update(func(nyms map[string]*Nym) error {
		k, _, err := nyms["dave"].ConsumeHsubKey()
		consumed = k
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, _ := Open(path)
	if err := s2.Unseal(pass(t, "pw")); err != nil {
		t.Fatal(err)
	}
	got, _ := s2.Get("dave")
	if got.HsubEpoch != 1 {
		t.Fatalf("epoch not persisted, got %d", got.HsubEpoch)
	}
	if got.HsubKey == consumed {
		t.Fatal("consumed key was persisted; the ratchet advance was lost")
	}
}

func TestLegacyNymHasNoRatchet(t *testing.T) {
	n := &Nym{Alias: "old", Mode: ModeLegacy, Flags: FlagNoForwardSecrecy}
	if _, _, err := n.ConsumeHsubKey(); !errors.Is(err, ErrWrongMode) {
		t.Fatalf("want ErrWrongMode, got %v", err)
	}
	if _, err := n.ConsumePrekey(); !errors.Is(err, ErrWrongMode) {
		t.Fatalf("want ErrWrongMode, got %v", err)
	}
	if !n.Flags.Has(FlagNoForwardSecrecy) {
		t.Fatal("legacy nyms must be flagged as non-forward-secret")
	}
}

func TestPrekeyConsumption(t *testing.T) {
	n := newNym(t, "erin")

	pks := make([]Prekey, 3)
	for i := range pks {
		pks[i].ID = uint64(i + 1)
		if _, err := rand.Read(pks[i].Pub[:]); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.AddPrekeys(pks); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		pk, err := n.ConsumePrekey()
		if err != nil {
			t.Fatal(err)
		}
		if pk.ID != uint64(i+1) {
			t.Fatalf("prekeys must be consumed in order: want %d, got %d", i+1, pk.ID)
		}
	}
	if _, err := n.ConsumePrekey(); !errors.Is(err, ErrPrekeyPoolEmpty) {
		t.Fatalf("want ErrPrekeyPoolEmpty, got %v", err)
	}
	if !n.NeedsPrekeyTopUp() {
		t.Fatal("empty pool must request a top-up")
	}
}

func TestPrekeyPoolCap(t *testing.T) {
	n := newNym(t, "frank")
	if err := n.AddPrekeys(make([]Prekey, PrekeyPoolMax+1)); !errors.Is(err, ErrPrekeyPoolFull) {
		t.Fatalf("want ErrPrekeyPoolFull, got %v", err)
	}
}

func TestReplayCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "pw"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}

	seen, err := s.SeenBefore("digest-a")
	if err != nil {
		t.Fatal(err)
	}
	if seen {
		t.Fatal("first sighting must not be a replay")
	}

	seen, err = s.SeenBefore("digest-a")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("second sighting must be reported as a replay")
	}
	s.Close()

	// Replay state must survive a restart, otherwise the whole cache is
	// theatre -- which is exactly the flaw in the original implementation.
	s2, _ := Open(path)
	if err := s2.Unseal(pass(t, "pw")); err != nil {
		t.Fatal(err)
	}
	seen, err = s2.SeenBefore("digest-a")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("replay cache did not survive reseal")
	}
}

func TestDayCounterResets(t *testing.T) {
	n := newNym(t, "grace")
	if got := n.BumpCounter(100); got != 1 {
		t.Fatalf("want 1, got %d", got)
	}
	if got := n.BumpCounter(100); got != 2 {
		t.Fatalf("want 2, got %d", got)
	}
	if got := n.BumpCounter(101); got != 1 {
		t.Fatalf("counter must reset on a new day, got %d", got)
	}
	if n.LastActiveDay != 101 {
		t.Fatalf("last active day not updated, got %d", n.LastActiveDay)
	}
}

func TestFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "pw"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("registry must be 0600, got %o", fi.Mode().Perm())
	}
}

func TestGetReturnsACopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.bin")
	s, err := Create(path, pass(t, "pw"), testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	n := newNym(t, "heidi")
	n.Prekeys = []Prekey{{ID: 1}}
	if err := s.Add(n); err != nil {
		t.Fatal(err)
	}

	got, _ := s.Get("heidi")
	got.HsubEpoch = 9999
	got.Prekeys[0].ID = 4242

	again, _ := s.Get("heidi")
	if again.HsubEpoch == 9999 || again.Prekeys[0].ID == 4242 {
		t.Fatal("Get must return a deep copy; registry state was mutated externally")
	}
}

func TestMain(m *testing.M) {
	memguard.CatchInterrupt()
	code := m.Run()
	memguard.Purge()
	os.Exit(code)
}
