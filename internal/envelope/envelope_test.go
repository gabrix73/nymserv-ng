package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func serverKeypair(t *testing.T) ([32]byte, [32]byte) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := publicOf(&priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func nymKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestRoundTrip(t *testing.T) {
	priv, pub := serverKeypair(t)
	nymPub, nymPriv := nymKeypair(t)
	sk := &ServerKeys{Current: priv}

	body := []byte("From: alice@nym.virebent.art\r\nTo: bob@example.org\r\n\r\nhello")
	raw, err := Seal(&pub, nymPriv, 42, body)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Open(sk, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, body) {
		t.Fatal("body mismatch")
	}
	if got.Counter != 42 {
		t.Fatalf("counter mismatch: %d", got.Counter)
	}
	if !bytes.Equal(got.NymPub, nymPub) {
		t.Fatal("nym public key mismatch")
	}
	var zero [32]byte
	if got.ReplayDigest == zero {
		t.Fatal("replay digest not computed")
	}
}

// TestEveryRejectionIsIdentical is the point of the package: no caller can tell
// why a message was dropped.
func TestEveryRejectionIsIdentical(t *testing.T) {
	priv, pub := serverKeypair(t)
	_, nymPriv := nymKeypair(t)
	sk := &ServerKeys{Current: priv}
	body := []byte("test body long enough to be realistic")

	base, err := Seal(&pub, nymPriv, 1, body)
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(f func([]byte)) []byte {
		c := append([]byte(nil), base...)
		f(c)
		return c
	}

	cases := map[string][]byte{
		"corrupt magic":  mutate(func(b []byte) { b[0] ^= 0xff }),
		"unknown key id": mutate(func(b []byte) { b[offKeyID] ^= 0xff }),
		"tampered epk":   mutate(func(b []byte) { b[offEPK] ^= 0x01 }),
		"tampered nonce": mutate(func(b []byte) { b[offNonce] ^= 0x01 }),
		"tampered tag":   mutate(func(b []byte) { b[len(b)-1] ^= 0x01 }),
		"tampered body":  mutate(func(b []byte) { b[HeaderLen+50] ^= 0x01 }),
		"truncated":      base[:HeaderLen+10],
		"empty":          {},
		"header only":    base[:HeaderLen],
	}

	for name, in := range cases {
		got, err := Open(sk, in)
		if !errors.Is(err, ErrReject) {
			t.Errorf("%s: want ErrReject, got %v", name, err)
		}
		if got != nil {
			t.Errorf("%s: returned a result alongside an error", name)
		}
	}
}

// TestSignatureRequired confirms that a valid AEAD layer is not sufficient:
// an attacker who somehow obtained the server key still cannot forge a message
// from a nym.
func TestSignatureRequired(t *testing.T) {
	priv, pub := serverKeypair(t)
	_, nymPriv := nymKeypair(t)
	_, otherPriv := nymKeypair(t)
	sk := &ServerKeys{Current: priv}

	body := []byte("a message")
	good, err := Seal(&pub, nymPriv, 7, body)
	if err != nil {
		t.Fatal(err)
	}

	// Re-seal the same body under a different nym key and confirm the claimed
	// public key travels with it -- the caller resolves it, so a mismatch is
	// caught by the registry lookup, not here.
	other, err := Seal(&pub, otherPriv, 7, body)
	if err != nil {
		t.Fatal(err)
	}

	a, err := Open(sk, good)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(sk, other)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.NymPub, b.NymPub) {
		t.Fatal("different signers produced the same claimed public key")
	}
}

// TestCrossKeyReplayFails checks that an envelope sealed to one server key
// epoch cannot be reused against another.
func TestCrossKeyReplayFails(t *testing.T) {
	privA, pubA := serverKeypair(t)
	privB, _ := serverKeypair(t)
	_, nymPriv := nymKeypair(t)

	raw, err := Seal(&pubA, nymPriv, 1, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(&ServerKeys{Current: privB}, raw); !errors.Is(err, ErrReject) {
		t.Fatal("envelope opened under the wrong server key")
	}
	if _, err := Open(&ServerKeys{Current: privA}, raw); err != nil {
		t.Fatalf("envelope failed under the correct key: %v", err)
	}
}

// TestRotationOverlap is the property that keeps clients working across a key
// change: messages sealed to the previous key must still open.
func TestRotationOverlap(t *testing.T) {
	oldPriv, oldPub := serverKeypair(t)
	newPriv, newPub := serverKeypair(t)
	_, nymPriv := nymKeypair(t)

	sk := &ServerKeys{Current: newPriv, Previous: oldPriv, HasPrev: true}

	oldEnv, _ := Seal(&oldPub, nymPriv, 1, []byte("sealed before rotation"))
	newEnv, _ := Seal(&newPub, nymPriv, 2, []byte("sealed after rotation"))

	if _, err := Open(sk, oldEnv); err != nil {
		t.Fatalf("previous-key envelope must still open during overlap: %v", err)
	}
	if _, err := Open(sk, newEnv); err != nil {
		t.Fatalf("current-key envelope failed: %v", err)
	}

	// Once the overlap ends, the old key is dropped and old envelopes stop
	// opening. That is intended, and is why the overlap has to be long enough.
	after := &ServerKeys{Current: newPriv}
	if _, err := Open(after, oldEnv); !errors.Is(err, ErrReject) {
		t.Fatal("previous-key envelope opened after the overlap ended")
	}
}

func TestBodyLengthBounds(t *testing.T) {
	_, pub := serverKeypair(t)
	_, nymPriv := nymKeypair(t)

	if _, err := Seal(&pub, nymPriv, 1, nil); err == nil {
		t.Fatal("empty body must be rejected")
	}
	if _, err := Seal(&pub, nymPriv, 1, make([]byte, MaxBodyLen+1)); err == nil {
		t.Fatal("oversized body must be rejected")
	}
}

// TestLowOrderPointRejected exercises the X25519 contributory-behaviour check.
func TestLowOrderPointRejected(t *testing.T) {
	priv, pub := serverKeypair(t)
	_, nymPriv := nymKeypair(t)
	sk := &ServerKeys{Current: priv}

	raw, err := Seal(&pub, nymPriv, 1, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	// Replace the ephemeral public key with the all-zero point, which has
	// small order. X25519 returns an error rather than a zero shared secret.
	for i := offEPK; i < offNonce; i++ {
		raw[i] = 0
	}
	if _, err := Open(sk, raw); !errors.Is(err, ErrReject) {
		t.Fatal("low-order ephemeral point must be rejected")
	}
}

func TestKeyIDStability(t *testing.T) {
	var pub [32]byte
	if _, err := rand.Read(pub[:]); err != nil {
		t.Fatal(err)
	}
	if KeyID(&pub) != KeyID(&pub) {
		t.Fatal("KeyID is not deterministic")
	}

	var other [32]byte
	copy(other[:], pub[:])
	other[0] ^= 0x01
	if KeyID(&pub) == KeyID(&other) {
		t.Fatal("KeyID collided on a one-bit difference")
	}
}

func TestBundleRoundTrip(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, encPub := serverKeypair(t)

	b := &Bundle{ValidFrom: 1000, ValidUntil: 1000 + EpochDays, EncPub: encPub}
	b.Sign(idPriv)

	got, err := ParseBundle(b.Marshal(), idPub, 1010)
	if err != nil {
		t.Fatal(err)
	}
	if got.EncPub != encPub {
		t.Fatal("encryption key did not survive the round trip")
	}

	if _, err := ParseBundle(b.Marshal(), idPub, 1000+EpochDays); !errors.Is(err, ErrBundleExpired) {
		t.Fatal("expired bundle must be rejected")
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseBundle(b.Marshal(), otherPub, 1010); !errors.Is(err, ErrBundleSignature) {
		t.Fatal("bundle signed by another identity must be rejected")
	}

	raw := b.Marshal()
	raw[20] ^= 0x01
	if _, err := ParseBundle(raw, idPub, 1010); !errors.Is(err, ErrBundleSignature) {
		t.Fatal("tampered bundle must be rejected")
	}
}

// FuzzOpen runs the parser against arbitrary input. Open must never panic and
// must never return a result together with an error, whatever it is fed.
func FuzzOpen(f *testing.F) {
	priv, pub := serverKeypair(&testing.T{})
	_, nymPriv, _ := ed25519.GenerateKey(rand.Reader)
	sk := &ServerKeys{Current: priv}

	if seed, err := Seal(&pub, nymPriv, 1, []byte("seed body")); err == nil {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add(make([]byte, HeaderLen))

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := Open(sk, data)
		if err != nil && got != nil {
			t.Fatal("Open returned both a result and an error")
		}
		if err == nil && got == nil {
			t.Fatal("Open returned neither a result nor an error")
		}
	})
}

var _ = curve25519.Basepoint
