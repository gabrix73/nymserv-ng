// Command nymserv-democlient seals a §3.2 envelope from the command line.
//
// This is a TEST HARNESS, not the real client. It exists so the ingest path can
// be exercised end to end before nymclient exists. It is missing everything
// that makes a client safe to use: it does not manage prekeys, does not run the
// hSub ratchet, does not poll the shared mailbox, does not talk to YAMN, and
// writes its key material to ordinary files.
//
// Do not use it for a real pseudonym.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"git.virebent.art/virebent/nymserv-ng/internal/envelope"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "seal":
		sealCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `nymserv-democlient -- TEST HARNESS, not the real client

  keygen -dir DIR
        Generate a nym Ed25519 identity and a random hSub key.

  seal -dir DIR -server-pub HEX -counter N [-in FILE]
        Seal stdin (or FILE) into an envelope on stdout.

The server public key comes from the 'keys' control command, or from a signed
bundle verified with nymserv-keytool bundle-verify.
`)
	os.Exit(64)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("dir", "", "output directory")
	fs.Parse(args)
	if *dir == "" {
		usage()
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	var hsub [32]byte
	if _, err := rand.Read(hsub[:]); err != nil {
		fatal(err)
	}

	write := func(name string, b []byte, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(*dir, name), []byte(hex.EncodeToString(b)+"\n"), mode); err != nil {
			fatal(err)
		}
	}
	write("nym.key", priv, 0o600)
	write("nym.pub", pub, 0o644)
	write("hsub.key", hsub[:], 0o600)

	fmt.Printf("identity: %s\n", hex.EncodeToString(pub))
	fmt.Printf("hsub:     %s\n", hex.EncodeToString(hsub[:]))
	fmt.Fprintln(os.Stderr, "\nRegister on the server with the control command:")
	fmt.Fprintf(os.Stderr, "  add-nym <alias> %s %s\n",
		hex.EncodeToString(pub), hex.EncodeToString(hsub[:]))
}

func sealCmd(args []string) {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	dir := fs.String("dir", "", "key directory from keygen")
	serverPub := fs.String("server-pub", "", "server X25519 public key, hex")
	counter := fs.String("counter", "", "envelope counter, must strictly increase")
	in := fs.String("in", "", "input file (default stdin)")
	b64 := fs.Bool("base64", false, "base64-encode the output")
	fs.Parse(args)

	if *dir == "" || *serverPub == "" || *counter == "" {
		usage()
	}

	privHex, err := os.ReadFile(filepath.Join(*dir, "nym.key"))
	if err != nil {
		fatal(err)
	}
	privRaw, err := hex.DecodeString(trimNL(string(privHex)))
	if err != nil || len(privRaw) != ed25519.PrivateKeySize {
		fatal(fmt.Errorf("nym.key is not a valid Ed25519 private key"))
	}

	spRaw, err := hex.DecodeString(trimNL(*serverPub))
	if err != nil || len(spRaw) != 32 {
		fatal(fmt.Errorf("server-pub must be 32 bytes of hex"))
	}
	var sp [32]byte
	copy(sp[:], spRaw)

	c, err := strconv.ParseUint(trimNL(*counter), 10, 64)
	if err != nil {
		fatal(err)
	}

	var body []byte
	if *in != "" {
		body, err = os.ReadFile(*in)
	} else {
		body, err = io.ReadAll(io.LimitReader(os.Stdin, envelope.MaxBodyLen+1))
	}
	if err != nil {
		fatal(err)
	}

	out, err := envelope.Seal(&sp, ed25519.PrivateKey(privRaw), c, body)
	if err != nil {
		fatal(err)
	}

	if *b64 {
		fmt.Println(base64.StdEncoding.EncodeToString(out))
		return
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fatal(err)
	}
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
