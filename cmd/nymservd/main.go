// Command nymservd is the long-running nymserv-ng daemon.
//
// It starts sealed. The ingest socket is bound immediately so the MTA is never
// refused, but nothing is processed until the operator supplies the registry
// passphrase over the control socket. Messages that arrive while sealed are
// held in a bounded buffer; when that fills, the delivery agent is told to
// defer and Postfix keeps them in its own queue.
//
// Run as: the dedicated `nymserv` system user. It never needs root and never
// binds a TCP port.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"git.virebent.art/virebent/nymserv-ng/internal/envelope"
	"git.virebent.art/virebent/nymserv-ng/internal/ingest"
	"git.virebent.art/virebent/nymserv-ng/internal/registry"
)

const (
	// holdingCapacity bounds how many messages are buffered while sealed or
	// while the dispatcher is behind. Bounded on purpose: an unbounded queue
	// is a memory-exhaustion primitive, and deferring to the MTA is strictly
	// better than dying.
	holdingCapacity = 1024

	ioTimeout = 30 * time.Second
)

type daemon struct {
	store   *registry.Store
	keys    atomic.Pointer[envelope.ServerKeys]
	spool   string
	holding chan *ingest.Frame

	// Aggregate counters only. There is deliberately no per-message record of
	// any kind: these are for an operator checking that the service is alive,
	// and they can never be correlated back to an alias or a time of arrival.
	accepted atomic.Uint64
	dropped  atomic.Uint64
}

func main() {
	var (
		dbPath      = flag.String("db", "/var/lib/nymserv/db/registry.bin", "sealed registry path")
		spoolPath   = flag.String("spool", "/var/lib/nymserv/spool/out", "outbound spool directory (must be tmpfs)")
		ingestSock  = flag.String("ingest-socket", "/run/nymserv/ingest.sock", "ingest socket path")
		controlSock = flag.String("control-socket", "/run/nymserv/control.sock", "control socket path")
		initDB      = flag.Bool("init", false, "create a new sealed registry and exit")
	)
	flag.Parse()

	memguard.CatchInterrupt()
	defer memguard.Purge()

	if *initDB {
		if err := doInit(*dbPath); err != nil {
			fmt.Fprintln(os.Stderr, "init failed:", err)
			os.Exit(1)
		}
		return
	}

	store, err := registry.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open registry:", err)
		os.Exit(1)
	}

	d := &daemon{
		store:   store,
		spool:   *spoolPath,
		holding: make(chan *ingest.Frame, holdingCapacity),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ingestLn, err := listenUnix(*ingestSock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ingest socket:", err)
		os.Exit(1)
	}
	defer ingestLn.Close()

	controlLn, err := listenUnix(*controlSock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "control socket:", err)
		os.Exit(1)
	}
	defer controlLn.Close()

	go d.serveIngest(ctx, ingestLn)
	go d.serveControl(ctx, controlLn)
	go d.dispatchLoop(ctx)
	go d.maintenanceLoop(ctx)

	<-ctx.Done()

	// Close wipes the in-memory registry and destroys the sealing key. The
	// holding buffer is deliberately *not* flushed: messages still in it were
	// never accepted, so Postfix will redeliver them.
	d.store.Close()
}

// doInit creates a fresh sealed registry. It is a separate mode rather than an
// implicit behaviour of startup, so a mistyped -db path can never silently
// create an empty registry alongside the real one.
func doInit(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	pass, err := readPassphrase("New registry passphrase: ")
	if err != nil {
		return err
	}
	defer pass.Destroy()

	store, err := registry.Create(path, pass, registry.DefaultKDFParams)
	if err != nil {
		return err
	}
	store.Close()
	fmt.Fprintln(os.Stderr, "registry created at", path)
	return nil
}

func listenUnix(path string) (net.Listener, error) {
	// A stale socket from an unclean shutdown would otherwise make every
	// restart fail. Removing it is safe because only one daemon instance is
	// ever meant to hold it, enforced by systemd, not by this file.
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// 0600: only the nymserv user. The control socket is reached by adding the
	// operator account to the owning group, not by widening this.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// serveIngest accepts frames from the delivery agent.
func (d *daemon) serveIngest(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go d.handleIngest(conn)
	}
}

func (d *daemon) handleIngest(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	frame, err := ingest.ReadFrame(conn)
	if err != nil {
		// No acknowledgement: the agent will exit EX_TEMPFAIL and Postfix
		// retries. A malformed frame from a local socket means a bug, not an
		// attack, and we would rather requeue than lose mail.
		return
	}

	select {
	case d.holding <- frame:
		_, _ = conn.Write([]byte{'K'})
	default:
		// Buffer full. Withhold the acknowledgement so the message stays in
		// the MTA queue rather than being accepted and then dropped.
	}
}

// dispatchLoop is the only place messages are processed. Serialising here
// means the registry's write lock is never contended by dispatch itself, and
// it makes the accept-then-release ordering easy to reason about.
func (d *daemon) dispatchLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-d.holding:
			if d.store.IsSealed() {
				// Put it back and wait. While sealed we make no progress by
				// design; the buffer drains once the operator unseals.
				select {
				case d.holding <- frame:
				default:
				}
				time.Sleep(2 * time.Second)
				continue
			}
			d.process(frame)
		}
	}
}

// process runs the §3.2 checks and either spools the message or drops it.
//
// Every failure path is identical from the outside: nothing is written, nothing
// is sent, no bounce is generated, and the only record is an aggregate counter.
// Distinguishing "unknown alias" from "bad signature" in any observable way
// would be an oracle for probing which aliases exist.
func (d *daemon) process(frame *ingest.Frame) {
	keys := d.keys.Load()
	if keys == nil {
		d.dropped.Add(1)
		return
	}

	opened, err := envelope.Open(keys, frame.Body)
	if err != nil {
		d.dropped.Add(1)
		return
	}

	var identity [registry.KeyLen]byte
	copy(identity[:], opened.NymPub)

	alias, err := d.store.Accept(identity, opened.Counter, opened.ReplayDigest)
	if err != nil {
		d.dropped.Add(1)
		return
	}

	// Routing is by the localpart the MTA resolved, not by anything inside the
	// message. `config` and `send` are the two service addresses; anything
	// else is mail for an alias.
	switch frame.Recipient {
	case "config":
		// TODO(§3.9): parse the Config: grammar and apply Nym-Command.
		// Until then the message is spooled unchanged so the path can be
		// exercised end to end.
	case "send":
		// TODO(§3.3): hand to the outbound module for YAMN submission.
	default:
		_ = alias
	}

	if err := d.spoolMessage(opened.Body); err != nil {
		d.dropped.Add(1)
		return
	}
	d.accepted.Add(1)
}

// spoolMessage writes an accepted message to the outbound spool.
//
// This is a placeholder for the pool and outbound modules. It writes straight
// through, which means there is currently NO mixing: arrival and release are
// correlated one to one. That is acceptable only because nothing is actually
// transmitted yet, and it must be replaced before the service carries real
// traffic.
//
// The spool must live on tmpfs with swap disabled. In-place overwriting is not
// reliable deletion on a journalled or copy-on-write filesystem, so the only
// way to make a deleted spool file unrecoverable is for it never to have been
// on stable storage.
func (d *daemon) spoolMessage(body []byte) error {
	if err := os.MkdirAll(d.spool, 0o700); err != nil {
		return err
	}

	var nameBytes [16]byte
	if _, err := rand.Read(nameBytes[:]); err != nil {
		return err
	}
	// Random name, never derived from time, PID or alias: the original
	// implementation built queue names from the PID and message identifiers
	// from the nanosecond clock, both of which leak directly.
	path := filepath.Join(d.spool, hex.EncodeToString(nameBytes[:]))

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(body); err != nil {
		os.Remove(path)
		return err
	}
	return f.Sync()
}

// serveControl handles the operator socket.
func (d *daemon) serveControl(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go d.handleControl(conn)
	}
}

func (d *daemon) handleControl(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	defer w.Flush()

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch trim(line) {
		case "unseal":
			d.controlUnseal(r, w)
		case "status":
			sealed := "unsealed"
			if d.store.IsSealed() {
				sealed = "sealed"
			}
			fmt.Fprintf(w, "%s accepted=%d dropped=%d held=%d\n",
				sealed, d.accepted.Load(), d.dropped.Load(), len(d.holding))
		case "keys":
			d.controlKeys(w)
		case "rotate":
			d.controlRotate(w)
		case "quit", "":
			return
		default:
			d.controlWithArgs(w, trim(line))
		}
		w.Flush()
	}
}

// controlUnseal reads a passphrase line and unseals the registry.
//
// The passphrase is moved into locked memory as soon as it is read and the
// intermediate buffer is wiped. It is never written to disk, never placed in
// an environment variable and never logged.
func (d *daemon) controlUnseal(r *bufio.Reader, w *bufio.Writer) {
	if !d.store.IsSealed() {
		fmt.Fprintln(w, "already unsealed")
		return
	}

	line, err := r.ReadString('\n')
	if err != nil {
		fmt.Fprintln(w, "read error")
		return
	}
	raw := []byte(trim(line))
	pass := memguard.NewBufferFromBytes(raw) // wipes raw
	defer pass.Destroy()

	if err := d.store.Unseal(pass); err != nil {
		// The operator is on the other end of this socket, not an attacker on
		// the network path, so a plain error is appropriate here -- and it is
		// still opaque about *why*, because a wrong passphrase and a corrupted
		// file are the same event to them.
		fmt.Fprintln(w, "unseal failed")
		return
	}

	if err := d.loadServerKeys(); err != nil {
		// A registry that has never been rotated has no encryption key yet,
		// and the only way to create one is from an unsealed store. Re-sealing
		// here would make first-time setup impossible.
		//
		// Staying unsealed without keys is safe: process() returns early when
		// no key is loaded, so every message is dropped rather than mishandled.
		fmt.Fprintln(w, "unsealed (no encryption key -- run 'rotate')")
		return
	}

	fmt.Fprintln(w, "unsealed")
}

// loadServerKeys reads the X25519 encryption keys from the unsealed registry.
//
// Both the current key and, while its overlap lasts, the previous one are
// installed. Without the previous key, every client that had not yet refetched
// the bundle at rotation time would produce ciphertext nobody could open.
func (d *daemon) loadServerKeys() error {
	cur, prev, hasPrev, err := d.store.ServerEncryptionKeys(registry.Today())
	if err != nil {
		return err
	}
	d.keys.Store(&envelope.ServerKeys{Current: cur, Previous: prev, HasPrev: hasPrev})
	return nil
}

// maintenanceLoop runs periodic work on a fixed schedule.
//
// Fixed, never traffic-driven: a maintenance pass whose timing depends on how
// much mail arrived is itself a side channel on message volume.
func (d *daemon) maintenanceLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if d.store.IsSealed() {
				continue
			}
			_, _ = d.store.ExpireReplay()
		}
	}
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// readPassphrase reads from the terminal without echo.
func readPassphrase(prompt string) (*memguard.LockedBuffer, error) {
	fmt.Fprint(os.Stderr, prompt)
	defer fmt.Fprintln(os.Stderr)

	fd := int(os.Stdin.Fd())
	state, err := disableEcho(fd)
	if err != nil {
		return nil, errors.New("stdin is not a terminal")
	}
	defer restoreEcho(fd, state)

	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return memguard.NewBufferFromBytes([]byte(trim(line))), nil
}
