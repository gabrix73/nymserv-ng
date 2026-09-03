// Package envelope implements the §3.2 inbound envelope: the authenticated,
// forward-secret wrapper that a nym owner puts around a message before handing
// it to YAMN.
//
// The security property that matters most in this package is not the
// cryptography, which is unremarkable, but the *uniformity of failure*. Every
// rejection reason -- unknown key id, bad AEAD tag, unknown nym, replayed
// counter, bad signature -- must be indistinguishable to the sender. Anything
// that leaks which check failed is an oracle for probing which aliases exist
// and which keys the server holds. Callers therefore get a single opaque error
// and must not branch on anything else.
package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Wire layout, §3.2:
//
//	offset  len  field
//	     0    8  magic "NYMSNG\x01\x00"
//	     8    8  key_id  = BLAKE2b-256(server enc_pk)[:8]
//	    16   32  epk     = X25519 ephemeral public key
//	    48   24  nonce
//	    72    n  ciphertext || Poly1305 tag
//
// Associated data is magic || key_id || epk. The nonce is not in the AD
// because it is already an AEAD input.
//
// Inner plaintext:
//
//	   0   32  nym_pk    Ed25519 public key of the claiming nym
//	  32    8  counter   strictly monotonic per nym, big-endian
//	  40    4  body_len  big-endian
//	  44    n  body
//	44+n   64  sig       Ed25519 over magic || key_id || epk || counter || body
const (
	magicLen = 8
	epkLen   = 32
	nonceLen = chacha20poly1305.NonceSizeX

	offKeyID  = magicLen
	offEPK    = offKeyID + KeyIDLen
	offNonce  = offEPK + epkLen
	HeaderLen = offNonce + nonceLen

	innerNymPKLen   = ed25519.PublicKeySize
	innerCounterLen = 8
	innerBodyLenLen = 4
	innerPrefixLen  = innerNymPKLen + innerCounterLen + innerBodyLenLen
	innerMinLen     = innerPrefixLen + ed25519.SignatureSize

	// MaxBodyLen is the largest body the envelope will carry. It matches the
	// largest padding bucket in §4.3; anything above it is rejected before any
	// cryptographic work is done.
	MaxBodyLen = 256 * 1024
)

var envelopeMagic = [magicLen]byte{'N', 'Y', 'M', 'S', 'N', 'G', 0x01, 0x00}

// ErrReject is the only error callers ever see from Open.
//
// It is deliberately uninformative. Do not add error wrapping that
// distinguishes causes, do not log which check failed on a per-message basis,
// and do not vary the response. The design document is explicit: there are no
// error replies and no differential behaviour on this path.
var ErrReject = errors.New("envelope: rejected")

// Opened is the result of a successful Open.
type Opened struct {
	// NymPub is the Ed25519 public key that authenticated the message. The
	// caller resolves it to an alias.
	NymPub ed25519.PublicKey

	// Counter is the sender's monotonic counter. The caller must compare it
	// against the stored value and reject anything not strictly greater, then
	// persist the new value before releasing the message.
	Counter uint64

	// Body is the RFC822 message or Config: block.
	Body []byte

	// ReplayDigest is BLAKE2b-256(epk || nonce), the key for the replay cache.
	// It is the backstop behind the counter check, bounding replay to the
	// cache TTL even if counter state is ever lost.
	ReplayDigest [32]byte
}

// Seal builds an envelope. This runs in the client, not in nymservd; it lives
// here so that both sides share one definition of the format and the test
// suite can exercise a real round trip.
func Seal(serverEncPub *[32]byte, nymPriv ed25519.PrivateKey, counter uint64, body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > MaxBodyLen {
		return nil, fmt.Errorf("envelope: body length %d out of range", len(body))
	}
	if len(nymPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("envelope: bad nym private key")
	}

	var esk [32]byte
	if _, err := rand.Read(esk[:]); err != nil {
		return nil, fmt.Errorf("envelope: ephemeral key: %w", err)
	}
	defer wipe(esk[:])

	epkSlice, err := curve25519.X25519(esk[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("envelope: ephemeral public: %w", err)
	}
	var epk [32]byte
	copy(epk[:], epkSlice)

	keyID := KeyID(serverEncPub)

	out := make([]byte, HeaderLen)
	copy(out[0:], envelopeMagic[:])
	copy(out[offKeyID:], keyID[:])
	copy(out[offEPK:], epk[:])
	nonce := out[offNonce:HeaderLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("envelope: nonce: %w", err)
	}

	key, err := deriveSharedKey(&esk, serverEncPub, &epk, serverEncPub)
	if err != nil {
		return nil, err
	}
	defer key.destroy()

	sig := ed25519.Sign(nymPriv, signedBytes(keyID, &epk, counter, body))

	inner := make([]byte, 0, innerPrefixLen+len(body)+ed25519.SignatureSize)
	inner = append(inner, nymPriv.Public().(ed25519.PublicKey)...)
	inner = binary.BigEndian.AppendUint64(inner, counter)
	inner = binary.BigEndian.AppendUint32(inner, uint32(len(body)))
	inner = append(inner, body...)
	inner = append(inner, sig...)
	defer wipe(inner)

	aead, err := chacha20poly1305.NewX(key.b[:])
	if err != nil {
		return nil, fmt.Errorf("envelope: aead: %w", err)
	}

	ad := make([]byte, 0, magicLen+KeyIDLen+epkLen)
	ad = append(ad, out[:offNonce]...)

	return aead.Seal(out, nonce, inner, ad), nil
}

// Open authenticates and decrypts an envelope.
//
// Every failure returns ErrReject and nothing else. The function deliberately
// performs the same sequence of operations on every path that it can, but note
// honestly what this does and does not buy: Go's runtime, allocator and GC make
// true constant-time behaviour across an AEAD failure unattainable, so the
// primary defence is that the *caller* emits no response at all, at any point,
// for any outcome. The uniformity here reduces the signal; the silence
// eliminates the channel.
func Open(sk *ServerKeys, raw []byte) (*Opened, error) {
	if len(raw) < HeaderLen+chacha20poly1305.Overhead+innerMinLen {
		return nil, ErrReject
	}
	if len(raw) > HeaderLen+chacha20poly1305.Overhead+innerMinLen+MaxBodyLen {
		return nil, ErrReject
	}
	if subtle.ConstantTimeCompare(raw[:magicLen], envelopeMagic[:]) != 1 {
		return nil, ErrReject
	}

	var keyID [KeyIDLen]byte
	copy(keyID[:], raw[offKeyID:offEPK])
	var epk [32]byte
	copy(epk[:], raw[offEPK:offNonce])
	nonce := raw[offNonce:HeaderLen]

	priv, ok := sk.selectKey(keyID)
	if !ok {
		return nil, ErrReject
	}
	serverPub, err := publicOf(priv)
	if err != nil {
		return nil, ErrReject
	}

	key, err := deriveSharedKey(priv, &epk, &epk, &serverPub)
	if err != nil {
		return nil, ErrReject
	}
	defer key.destroy()

	aead, err := chacha20poly1305.NewX(key.b[:])
	if err != nil {
		return nil, ErrReject
	}

	ad := raw[:offNonce]
	inner, err := aead.Open(nil, nonce, raw[HeaderLen:], ad)
	if err != nil {
		return nil, ErrReject
	}
	defer wipe(inner)

	if len(inner) < innerMinLen {
		return nil, ErrReject
	}

	nymPub := make(ed25519.PublicKey, innerNymPKLen)
	copy(nymPub, inner[:innerNymPKLen])
	counter := binary.BigEndian.Uint64(inner[innerNymPKLen:])
	bodyLen := int(binary.BigEndian.Uint32(inner[innerNymPKLen+innerCounterLen:]))

	// Reject a declared length that does not match the actual layout. Trusting
	// it would be a buffer-overread primitive.
	if bodyLen <= 0 || bodyLen > MaxBodyLen {
		return nil, ErrReject
	}
	if len(inner) != innerPrefixLen+bodyLen+ed25519.SignatureSize {
		return nil, ErrReject
	}

	body := inner[innerPrefixLen : innerPrefixLen+bodyLen]
	sig := inner[innerPrefixLen+bodyLen:]

	if !ed25519.Verify(nymPub, signedBytes(keyID, &epk, counter, body), sig) {
		return nil, ErrReject
	}

	// Copy the body out before the deferred wipe clears the inner buffer.
	bodyCopy := make([]byte, bodyLen)
	copy(bodyCopy, body)

	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, ErrReject
	}
	h.Write(epk[:])
	h.Write(nonce)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))

	return &Opened{
		NymPub:       nymPub,
		Counter:      counter,
		Body:         bodyCopy,
		ReplayDigest: digest,
	}, nil
}

// signedBytes builds the exact byte string covered by the nym's signature.
//
// key_id and epk are included so that a captured envelope cannot be re-sealed
// to a different server key or a different ephemeral key while keeping a valid
// signature.
func signedBytes(keyID [KeyIDLen]byte, epk *[32]byte, counter uint64, body []byte) []byte {
	out := make([]byte, 0, magicLen+KeyIDLen+epkLen+8+len(body))
	out = append(out, envelopeMagic[:]...)
	out = append(out, keyID[:]...)
	out = append(out, epk[:]...)
	out = binary.BigEndian.AppendUint64(out, counter)
	return append(out, body...)
}

// sharedKey wraps the derived AEAD key so it is wiped on a deferred call
// rather than left to the garbage collector.
type sharedKey struct{ b [32]byte }

func (k *sharedKey) destroy() { wipe(k.b[:]) }

// deriveSharedKey computes
//
//	BLAKE2b-256(X25519(priv, peer) || epk || server_enc_pk)
//
// Binding both the ephemeral and the server key into the KDF input means the
// resulting key is unusable in any other pairing, which is what stops an
// attacker replaying an envelope against a different server key epoch.
func deriveSharedKey(priv, peer, epk, serverPub *[32]byte) (*sharedKey, error) {
	shared, err := curve25519.X25519(priv[:], peer[:])
	if err != nil {
		// A low-order or otherwise invalid peer point lands here. X25519
		// already rejects all-zero outputs, so no separate contributory
		// behaviour check is needed.
		return nil, fmt.Errorf("envelope: x25519: %w", err)
	}
	defer wipe(shared)

	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: blake2b: %w", err)
	}
	h.Write(shared)
	h.Write(epk[:])
	h.Write(serverPub[:])

	k := &sharedKey{}
	copy(k.b[:], h.Sum(nil))
	return k, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
