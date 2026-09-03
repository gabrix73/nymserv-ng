package registry

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Sealed blob layout. Every field before the ciphertext is authenticated as
// associated data, so an attacker cannot downgrade the KDF parameters and then
// present the result as a valid file.
//
//	offset  len  field
//	     0    8  magic "NYMSNGR1"
//	     8    1  format version
//	     9    1  KDF identifier (1 = Argon2id)
//	    10    4  Argon2 time cost, big-endian
//	    14    4  Argon2 memory cost in KiB, big-endian
//	    18    1  Argon2 parallelism
//	    19   16  salt
//	    35   24  XChaCha20-Poly1305 nonce
//	    59    n  ciphertext || Poly1305 tag
const (
	magic         = "NYMSNGR1"
	formatVersion = 1
	kdfArgon2id   = 1

	saltLen    = 16
	sealKeyLen = 32

	offVersion  = 8
	offKDF      = 9
	offTime     = 10
	offMemory   = 14
	offParallel = 18
	offSalt     = 19
	offNonce    = offSalt + saltLen
	headerLen   = offNonce + chacha20poly1305.NonceSizeX
)

var (
	ErrBadMagic      = errors.New("registry: not a nymserv-ng registry file")
	ErrBadVersion    = errors.New("registry: unsupported registry format version")
	ErrBadKDF        = errors.New("registry: unsupported key derivation function")
	ErrTruncated     = errors.New("registry: registry file is truncated")
	ErrUnsealFailed  = errors.New("registry: unseal failed (wrong passphrase or corrupted file)")
	ErrWeakKDFParams = errors.New("registry: refusing KDF parameters below the minimum")
)

// KDFParams are the Argon2id cost parameters. They are stored in the file
// header so that a registry sealed with one set of parameters can still be
// opened after the defaults change.
type KDFParams struct {
	Time        uint32 // iterations
	MemoryKiB   uint32 // memory cost in KiB
	Parallelism uint8
}

// DefaultKDFParams targets a host with at least 4 GB of RAM. The allocation is
// transient and only occurs during unseal, which happens once per restart, so
// several seconds of work is the right trade against an offline attack on a
// seized blob.
var DefaultKDFParams = KDFParams{
	Time:        3,
	MemoryKiB:   256 * 1024, // 256 MiB
	Parallelism: 4,
}

// MinKDFParams is the floor accepted when opening a file. It exists so that a
// tampered header cannot force a trivially cheap derivation; the header is
// authenticated, but the parameters are read before the tag is verified, so
// they are validated independently.
var MinKDFParams = KDFParams{
	Time:        1,
	MemoryKiB:   32 * 1024, // 32 MiB
	Parallelism: 1,
}

func (p KDFParams) validate() error {
	if p.Time < MinKDFParams.Time ||
		p.MemoryKiB < MinKDFParams.MemoryKiB ||
		p.Parallelism < MinKDFParams.Parallelism {
		return ErrWeakKDFParams
	}
	return nil
}

// deriveKey runs Argon2id over the passphrase and returns the result in locked
// memory. The caller owns the returned buffer and must Destroy it.
//
// The passphrase buffer belongs to the caller and is not consumed here.
func deriveKey(passphrase *memguard.LockedBuffer, salt []byte, p KDFParams) (*memguard.LockedBuffer, error) {
	if passphrase == nil || !passphrase.IsAlive() {
		return nil, errors.New("registry: passphrase buffer is not usable")
	}
	if err := p.validate(); err != nil {
		return nil, err
	}

	raw := argon2.IDKey(
		passphrase.Bytes(),
		salt,
		p.Time,
		p.MemoryKiB,
		p.Parallelism,
		sealKeyLen,
	)

	// NewBufferFromBytes wipes the source slice, so the Argon2 output does not
	// survive on the ordinary heap.
	return memguard.NewBufferFromBytes(raw), nil
}

// seal encrypts plaintext into a complete registry file image.
//
// plaintext is wiped before returning, whether or not sealing succeeded.
func seal(plaintext []byte, key *memguard.LockedBuffer, p KDFParams, salt []byte) ([]byte, error) {
	defer wipe(plaintext)

	if len(salt) != saltLen {
		return nil, fmt.Errorf("registry: salt must be %d bytes", saltLen)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("registry: aead init: %w", err)
	}

	out := make([]byte, headerLen, headerLen+len(plaintext)+aead.Overhead())
	copy(out[0:], magic)
	out[offVersion] = formatVersion
	out[offKDF] = kdfArgon2id
	binary.BigEndian.PutUint32(out[offTime:], p.Time)
	binary.BigEndian.PutUint32(out[offMemory:], p.MemoryKiB)
	out[offParallel] = p.Parallelism
	copy(out[offSalt:], salt)

	nonce := out[offNonce:headerLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("registry: nonce: %w", err)
	}

	// The whole header, nonce included, is the associated data.
	header := make([]byte, headerLen)
	copy(header, out[:headerLen])

	return aead.Seal(out, nonce, plaintext, header), nil
}

// parseHeader reads and validates the unauthenticated header fields.
func parseHeader(blob []byte) (KDFParams, []byte, []byte, error) {
	var p KDFParams

	if len(blob) < headerLen+chacha20poly1305.Overhead {
		return p, nil, nil, ErrTruncated
	}
	if string(blob[:len(magic)]) != magic {
		return p, nil, nil, ErrBadMagic
	}
	if blob[offVersion] != formatVersion {
		return p, nil, nil, ErrBadVersion
	}
	if blob[offKDF] != kdfArgon2id {
		return p, nil, nil, ErrBadKDF
	}

	p.Time = binary.BigEndian.Uint32(blob[offTime:])
	p.MemoryKiB = binary.BigEndian.Uint32(blob[offMemory:])
	p.Parallelism = blob[offParallel]
	if err := p.validate(); err != nil {
		return p, nil, nil, err
	}

	salt := blob[offSalt : offSalt+saltLen]
	nonce := blob[offNonce:headerLen]
	return p, salt, nonce, nil
}

// unseal derives the key from the passphrase and decrypts the blob. The
// returned plaintext is ordinary heap memory and must be wiped by the caller
// once parsed. The derived key is returned so the store can hold it for
// subsequent saves.
func unseal(blob []byte, passphrase *memguard.LockedBuffer) ([]byte, *memguard.LockedBuffer, KDFParams, error) {
	p, salt, nonce, err := parseHeader(blob)
	if err != nil {
		return nil, nil, p, err
	}

	key, err := deriveKey(passphrase, salt, p)
	if err != nil {
		return nil, nil, p, err
	}

	aead, err := chacha20poly1305.NewX(key.Bytes())
	if err != nil {
		key.Destroy()
		return nil, nil, p, fmt.Errorf("registry: aead init: %w", err)
	}

	header := make([]byte, headerLen)
	copy(header, blob[:headerLen])

	plaintext, err := aead.Open(nil, nonce, blob[headerLen:], header)
	if err != nil {
		key.Destroy()
		// Deliberately opaque: a wrong passphrase and a tampered file are the
		// same event to the operator, and distinguishing them helps nobody.
		return nil, nil, p, ErrUnsealFailed
	}

	return plaintext, key, p, nil
}

// wipe overwrites a byte slice. This is best-effort defence against the value
// lingering on the heap; it is not secure deletion of anything already written
// to storage.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
