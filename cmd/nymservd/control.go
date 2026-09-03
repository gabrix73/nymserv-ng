package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"git.virebent.art/virebent/nymserv-ng/internal/envelope"
	"git.virebent.art/virebent/nymserv-ng/internal/ingest"
	"git.virebent.art/virebent/nymserv-ng/internal/registry"
)

// Control commands taking arguments.
//
// This socket is mode 0600 on a unix path and is reached over SSH through an
// onion service. It is an operator interface, so plain error messages are
// appropriate here -- unlike the mail path, where any differential response is
// an oracle.
func (d *daemon) controlWithArgs(w *bufio.Writer, line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}

	switch fields[0] {
	case "set-identity":
		if len(fields) != 2 {
			fmt.Fprintln(w, "usage: set-identity <hex ed25519 public key>")
			return
		}
		pub, err := hex.DecodeString(fields[1])
		if err != nil || len(pub) != ed25519.PublicKeySize {
			fmt.Fprintln(w, "identity key must be 32 bytes of hex")
			return
		}
		if err := d.store.SetIdentity(pub); err != nil {
			fmt.Fprintln(w, "error:", err)
			return
		}
		fmt.Fprintln(w, "identity pinned")

	case "import-bundle":
		if len(fields) != 2 {
			fmt.Fprintln(w, "usage: import-bundle <base64 bundle>")
			return
		}
		d.controlImportBundle(w, fields[1])

	case "add-nym":
		if len(fields) != 4 {
			fmt.Fprintln(w, "usage: add-nym <alias> <hex ed25519 identity> <hex hsub key>")
			return
		}
		d.controlAddNym(w, fields[1], fields[2], fields[3])

	case "disable", "enable":
		if len(fields) != 2 {
			fmt.Fprintf(w, "usage: %s <alias>\n", fields[0])
			return
		}
		d.controlToggle(w, fields[0] == "disable", fields[1])

	default:
		fmt.Fprintln(w, "unknown command")
	}
}

func (d *daemon) controlKeys(w *bufio.Writer) {
	if d.store.IsSealed() {
		fmt.Fprintln(w, "sealed")
		return
	}

	id, err := d.store.Identity()
	if err != nil {
		fmt.Fprintln(w, "identity: none pinned")
	} else {
		fmt.Fprintf(w, "identity: %s\n", hex.EncodeToString(id))
	}

	e, err := d.store.CurrentPublic()
	if err != nil {
		fmt.Fprintln(w, "encryption key: none -- run 'rotate'")
		return
	}
	fmt.Fprintf(w, "encryption key: %s valid %d..%d\n",
		hex.EncodeToString(e.Pub[:]), e.From, e.Until)

	if b, err := d.store.Bundle(); err == nil {
		fmt.Fprintf(w, "bundle: present (%d bytes)\n", len(b))
	} else {
		fmt.Fprintln(w, "bundle: none -- sign the encryption key offline and import it")
	}
}

// controlRotate generates a new encryption epoch.
//
// It deliberately does not publish anything: the new key is unusable by clients
// until a bundle signed with the offline identity key is imported. That gap is
// the design working, not a missing step.
func (d *daemon) controlRotate(w *bufio.Writer) {
	if d.store.IsSealed() {
		fmt.Fprintln(w, "sealed")
		return
	}

	e, err := d.store.RotateKey(registry.Today())
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return
	}
	if err := d.loadServerKeys(); err != nil {
		fmt.Fprintln(w, "error:", err)
		return
	}

	fmt.Fprintf(w, "new encryption key: %s valid %d..%d\n",
		hex.EncodeToString(e.Pub[:]), e.From, e.Until)
	fmt.Fprintln(w, "sign it on the offline machine:")
	fmt.Fprintf(w, "  nymserv-keytool bundle-sign -identity identity.key -enc-pub %s\n",
		hex.EncodeToString(e.Pub[:]))
}

func (d *daemon) controlImportBundle(w *bufio.Writer, b64 string) {
	if d.store.IsSealed() {
		fmt.Fprintln(w, "sealed")
		return
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		fmt.Fprintln(w, "bundle is not valid base64")
		return
	}

	id, err := d.store.Identity()
	if err != nil {
		fmt.Fprintln(w, "no identity key pinned; run set-identity first")
		return
	}

	// Verify before storing. A bundle that does not match the pinned identity
	// is refused outright: accepting it would let anyone who reaches this
	// socket redirect clients to a key they control.
	b, err := envelope.ParseBundle(raw, id, registry.Today())
	if err != nil {
		fmt.Fprintln(w, "bundle rejected:", err)
		return
	}

	e, err := d.store.CurrentPublic()
	if err != nil {
		fmt.Fprintln(w, "no encryption key to bind the bundle to")
		return
	}
	if b.EncPub != e.Pub {
		fmt.Fprintln(w, "bundle does not describe the current encryption key")
		return
	}

	if err := d.store.SetBundle(raw); err != nil {
		fmt.Fprintln(w, "error:", err)
		return
	}
	fmt.Fprintln(w, "bundle imported")
}

// controlAddNym registers a nym directly.
//
// This is an operator path for testing and for recovery. Normal registration
// goes through a signed Config: block on the mail path (§3.9); nothing about
// this command bypasses the authentication that path performs, because the
// identity key supplied here is what every later message must be signed by.
func (d *daemon) controlAddNym(w *bufio.Writer, alias, idHex, hsubHex string) {
	if d.store.IsSealed() {
		fmt.Fprintln(w, "sealed")
		return
	}
	if !ingest.ValidRecipient(alias) {
		fmt.Fprintln(w, "invalid alias")
		return
	}

	idRaw, err := hex.DecodeString(idHex)
	if err != nil || len(idRaw) != ed25519.PublicKeySize {
		fmt.Fprintln(w, "identity key must be 32 bytes of hex")
		return
	}
	hsubRaw, err := hex.DecodeString(hsubHex)
	if err != nil || len(hsubRaw) != registry.KeyLen {
		fmt.Fprintln(w, "hsub key must be 32 bytes of hex")
		return
	}

	n := &registry.Nym{Alias: alias, Mode: registry.ModeModern}
	copy(n.IdentityKey[:], idRaw)
	copy(n.HsubKey[:], hsubRaw)

	if err := d.store.Add(n); err != nil {
		fmt.Fprintln(w, "error:", err)
		return
	}
	fmt.Fprintln(w, "registered")
}

func (d *daemon) controlToggle(w *bufio.Writer, disable bool, alias string) {
	if d.store.IsSealed() {
		fmt.Fprintln(w, "sealed")
		return
	}

	err := d.store.Update(func(nyms map[string]*registry.Nym) error {
		n, ok := nyms[alias]
		if !ok {
			return registry.ErrNoSuchNym
		}
		if disable {
			n.Flags |= registry.FlagDisabled
		} else {
			n.Flags &^= registry.FlagDisabled
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return
	}
	fmt.Fprintln(w, "ok")
}
