// Command nymserv-keytool runs on an OFFLINE machine.
//
// It holds the server identity private key, which must never exist on the VPS.
// Its only jobs are generating that key once and signing encryption-key
// bundles. Keeping it separate is the whole point of the key hierarchy in §2.4:
// an attacker who compromises the running server can read mail, but cannot
// produce a bundle and therefore cannot impersonate the server to clients.
//
// Run as: an ordinary user on a machine with no network. Never on the server.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"git.virebent.art/virebent/nymserv-ng/internal/envelope"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "identity-gen":
		identityGen(os.Args[2:])
	case "bundle-sign":
		bundleSign(os.Args[2:])
	case "bundle-verify":
		bundleVerify(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `nymserv-keytool -- offline server identity operations

  identity-gen  -dir DIR
        Generate the server identity keypair. Writes identity.key (0600) and
        identity.pub. Run once, on an offline machine, and keep DIR off the
        server permanently.

  bundle-sign   -identity FILE -enc-pub HEX [-from DAY] [-until DAY]
        Sign an encryption-key bundle for the public key reported by
        'nymservd rotate'. Prints the bundle in base64.

  bundle-verify -identity-pub FILE -bundle BASE64 [-day DAY]
        Verify a bundle against a pinned identity public key.

Day numbers are days since the Unix epoch, UTC. Omitted, they default to today
and today+90.
`)
	os.Exit(64)
}

func today() uint32 { return uint32(time.Now().UTC().Unix() / 86400) }

func identityGen(args []string) {
	fs := flag.NewFlagSet("identity-gen", flag.ExitOnError)
	dir := fs.String("dir", "", "output directory")
	fs.Parse(args)

	if *dir == "" {
		usage()
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fatal(err)
	}

	privPath := filepath.Join(*dir, "identity.key")
	if _, err := os.Stat(privPath); err == nil {
		fatal(fmt.Errorf("%s already exists; refusing to overwrite an identity key", privPath))
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}

	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "identity.pub"), []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		fatal(err)
	}

	fmt.Printf("identity public key: %s\n", hex.EncodeToString(pub))
	fmt.Fprintln(os.Stderr, "\nPin this public key on the server with 'nymservd' control command:")
	fmt.Fprintf(os.Stderr, "  set-identity %s\n", hex.EncodeToString(pub))
	fmt.Fprintln(os.Stderr, "\nPublish the same value for clients to pin. Keep identity.key offline.")
}

func bundleSign(args []string) {
	fs := flag.NewFlagSet("bundle-sign", flag.ExitOnError)
	idFile := fs.String("identity", "", "identity.key path")
	encPub := fs.String("enc-pub", "", "encryption public key, hex")
	from := fs.String("from", "", "valid-from day number")
	until := fs.String("until", "", "valid-until day number")
	fs.Parse(args)

	if *idFile == "" || *encPub == "" {
		usage()
	}

	priv, err := readIdentity(*idFile)
	if err != nil {
		fatal(err)
	}

	raw, err := hex.DecodeString(trimNL(*encPub))
	if err != nil || len(raw) != 32 {
		fatal(fmt.Errorf("enc-pub must be 32 bytes of hex"))
	}

	b := &envelope.Bundle{ValidFrom: today(), ValidUntil: today() + envelope.EpochDays}
	if *from != "" {
		b.ValidFrom = uint32(mustUint(*from))
	}
	if *until != "" {
		b.ValidUntil = uint32(mustUint(*until))
	}
	copy(b.EncPub[:], raw)
	b.Sign(priv)

	fmt.Println(base64.StdEncoding.EncodeToString(b.Marshal()))
	fmt.Fprintf(os.Stderr, "\nvalid days %d..%d (exclusive)\n", b.ValidFrom, b.ValidUntil)
	fmt.Fprintln(os.Stderr, "Import on the server with the control command:")
	fmt.Fprintln(os.Stderr, "  import-bundle <base64>")
}

func bundleVerify(args []string) {
	fs := flag.NewFlagSet("bundle-verify", flag.ExitOnError)
	pubFile := fs.String("identity-pub", "", "identity.pub path")
	bundle := fs.String("bundle", "", "bundle, base64")
	day := fs.String("day", "", "day number to check validity against")
	fs.Parse(args)

	if *pubFile == "" || *bundle == "" {
		usage()
	}

	pubHex, err := os.ReadFile(*pubFile)
	if err != nil {
		fatal(err)
	}
	pub, err := hex.DecodeString(trimNL(string(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fatal(fmt.Errorf("identity.pub must be 32 bytes of hex"))
	}

	raw, err := base64.StdEncoding.DecodeString(trimNL(*bundle))
	if err != nil {
		fatal(err)
	}

	d := today()
	if *day != "" {
		d = uint32(mustUint(*day))
	}

	b, err := envelope.ParseBundle(raw, pub, d)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("valid: enc-pub=%s days %d..%d\n",
		hex.EncodeToString(b.EncPub[:]), b.ValidFrom, b.ValidUntil)
}

func readIdentity(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := hex.DecodeString(trimNL(string(raw)))
	if err != nil {
		return nil, err
	}
	if len(dec) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity key must be %d bytes", ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(dec), nil
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func mustUint(s string) uint64 {
	v, err := strconv.ParseUint(trimNL(s), 10, 32)
	if err != nil {
		fatal(err)
	}
	return v
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
