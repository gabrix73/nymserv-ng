// Command nymserv-lda is the local delivery agent invoked by the MTA.
//
// It does as little as possible on purpose: read stdin under a hard cap,
// forward it to nymservd over a unix socket, exit. It holds no state, performs
// no cryptography, parses no headers and writes nothing to stdout or stderr.
//
// The silence is a requirement, not tidiness. An LDA's stderr is captured by
// Postfix and written to the mail log with a timestamp, so anything printed
// here becomes a durable record of which alias received mail and when --
// exactly the metadata this server exists to not keep.
//
// Run as: the dedicated `nymserv` system user, via a pipe transport in
// master.cf. It never needs root.
package main

import (
	"flag"
	"net"
	"os"
	"strings"
	"time"

	"git.virebent.art/virebent/nymserv-ng/internal/ingest"
)

// sysexits codes. EX_TEMPFAIL makes Postfix keep the message in its queue and
// retry, which is what we want whenever the daemon is unreachable or sealed:
// the message is deferred, never silently lost.
const (
	exOK       = 0
	exUsage    = 64
	exDataErr  = 65
	exNoUser   = 67
	exTempFail = 75
)

const dialTimeout = 10 * time.Second

func main() {
	socket := flag.String("socket", "/run/nymserv/ingest.sock", "nymservd ingest socket")
	flag.Parse()

	// The recipient localpart is the only argument, supplied by the MTA as
	// ${user}. Note the deliberate use of flag.Args() after registering real
	// flags: the original implementation called flag.Parse() with none
	// registered, so any leading dash argument aborted the process before it
	// ran at all.
	args := flag.Args()
	if len(args) != 1 {
		os.Exit(exUsage)
	}

	recipient := strings.ToLower(strings.TrimSpace(args[0]))
	if !ingest.ValidRecipient(recipient) {
		// Unknown or malformed localpart. EX_NOUSER tells the MTA to bounce at
		// its own layer, which reveals nothing the MTA did not already know.
		os.Exit(exNoUser)
	}

	body, err := ingest.ReadCapped(os.Stdin)
	if err != nil {
		os.Exit(exDataErr)
	}

	conn, err := net.DialTimeout("unix", *socket, dialTimeout)
	if err != nil {
		os.Exit(exTempFail)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(dialTimeout))

	if err := ingest.WriteFrame(conn, &ingest.Frame{Recipient: recipient, Body: body}); err != nil {
		os.Exit(exTempFail)
	}

	// Wait for the daemon's single-byte acknowledgement before exiting. Without
	// it, a daemon that dies mid-write would look like a successful delivery
	// and Postfix would drop the message.
	ack := make([]byte, 1)
	if _, err := conn.Read(ack); err != nil || ack[0] != 'K' {
		os.Exit(exTempFail)
	}

	os.Exit(exOK)
}
