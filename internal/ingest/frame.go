// Package ingest defines the wire format between nymserv-lda and nymservd.
//
// The split exists because the original implementation was a per-message
// process holding its state in memory, which made replay protection and the
// confirmation flow structurally impossible. Here the delivery agent is
// deliberately trivial -- it reads, forwards and exits -- and every piece of
// state lives in the long-running daemon.
package ingest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxRecipientLen bounds the localpart the MTA hands us.
	MaxRecipientLen = 64

	// MaxMessageLen is the hard ceiling on an inbound message, checked before
	// any parsing anywhere. It matches the largest padding bucket plus room
	// for envelope and transport overhead.
	MaxMessageLen = 300 * 1024

	frameMagic = uint32(0x4E594D31) // "NYM1"
)

var (
	ErrOversize     = errors.New("ingest: message exceeds the size limit")
	ErrBadFrame     = errors.New("ingest: malformed frame")
	ErrBadRecipient = errors.New("ingest: invalid recipient")
)

// Frame is one message handed from the delivery agent to the daemon.
type Frame struct {
	// Recipient is the localpart the MTA resolved, lowercased. It is the only
	// routing information the daemon uses; the daemon never inspects RFC822
	// headers for routing.
	Recipient string

	// Body is the raw message as received, headers included.
	Body []byte
}

// ValidRecipient reports whether a localpart is acceptable.
//
// The character set is intentionally narrow. A localpart reaches paths that
// build filenames and command arguments, and the cheapest defence against
// traversal and injection is refusing anything that is not obviously safe.
func ValidRecipient(s string) bool {
	if len(s) < 2 || len(s) > MaxRecipientLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '+':
		default:
			return false
		}
	}
	return true
}

// WriteFrame serialises a frame onto w.
//
//	magic(4) || recipient_len(2) || body_len(4) || recipient || body
func WriteFrame(w io.Writer, f *Frame) error {
	if !ValidRecipient(f.Recipient) {
		return ErrBadRecipient
	}
	if len(f.Body) > MaxMessageLen {
		return ErrOversize
	}

	hdr := make([]byte, 10)
	binary.BigEndian.PutUint32(hdr[0:], frameMagic)
	binary.BigEndian.PutUint16(hdr[4:], uint16(len(f.Recipient)))
	binary.BigEndian.PutUint32(hdr[6:], uint32(len(f.Body)))

	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("ingest: write header: %w", err)
	}
	if _, err := io.WriteString(w, f.Recipient); err != nil {
		return fmt.Errorf("ingest: write recipient: %w", err)
	}
	if _, err := w.Write(f.Body); err != nil {
		return fmt.Errorf("ingest: write body: %w", err)
	}
	return nil
}

// ReadFrame reads one frame from r, enforcing every bound before allocating.
func ReadFrame(r io.Reader) (*Frame, error) {
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(hdr[0:]) != frameMagic {
		return nil, ErrBadFrame
	}

	rlen := int(binary.BigEndian.Uint16(hdr[4:]))
	blen := int(binary.BigEndian.Uint32(hdr[6:]))

	// Bound before allocating: a declared length is attacker-controlled even
	// on a local socket, and trusting it is a memory-exhaustion primitive.
	if rlen < 2 || rlen > MaxRecipientLen {
		return nil, ErrBadFrame
	}
	if blen < 1 || blen > MaxMessageLen {
		return nil, ErrOversize
	}

	buf := make([]byte, rlen+blen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	f := &Frame{Recipient: string(buf[:rlen]), Body: buf[rlen:]}
	if !ValidRecipient(f.Recipient) {
		return nil, ErrBadRecipient
	}
	return f, nil
}

// ReadCapped reads at most MaxMessageLen+1 bytes and fails if the input is
// longer, rather than truncating. Truncating would hand the daemon a message
// that fails authentication for the wrong reason.
func ReadCapped(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxMessageLen+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxMessageLen {
		return nil, ErrOversize
	}
	if len(body) == 0 {
		return nil, ErrBadFrame
	}
	return body, nil
}
