package ingest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	in := &Frame{Recipient: "alice", Body: []byte("hello world")}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Recipient != in.Recipient || !bytes.Equal(out.Body, in.Body) {
		t.Fatal("frame did not survive the round trip")
	}
}

func TestRecipientValidation(t *testing.T) {
	good := []string{"alice", "bob-1", "a_b", "user+tag", "confirm"}
	bad := []string{"", "a", "../etc/passwd", "Alice", "a b", "x;rm -rf /",
		"user@host", strings.Repeat("a", MaxRecipientLen+1)}

	for _, s := range good {
		if !ValidRecipient(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if ValidRecipient(s) {
			t.Errorf("%q should be rejected", s)
		}
	}
}

// TestDeclaredLengthBounded checks that a lying length header cannot make the
// reader allocate. The socket is local, but a declared length is still
// attacker-influenced input.
func TestDeclaredLengthBounded(t *testing.T) {
	hdr := make([]byte, 10)
	binary.BigEndian.PutUint32(hdr[0:], frameMagic)
	binary.BigEndian.PutUint16(hdr[4:], 5)
	binary.BigEndian.PutUint32(hdr[6:], 0xFFFFFFFF)

	if _, err := ReadFrame(bytes.NewReader(hdr)); !errors.Is(err, ErrOversize) {
		t.Fatalf("want ErrOversize, got %v", err)
	}
}

func TestBadMagicRejected(t *testing.T) {
	hdr := make([]byte, 10)
	binary.BigEndian.PutUint32(hdr[0:], 0xDEADBEEF)
	binary.BigEndian.PutUint16(hdr[4:], 5)
	binary.BigEndian.PutUint32(hdr[6:], 5)

	if _, err := ReadFrame(bytes.NewReader(append(hdr, []byte("aliceXXXXX")...))); !errors.Is(err, ErrBadFrame) {
		t.Fatal("bad magic must be rejected")
	}
}

// TestReadCappedRefusesTruncation confirms oversized input fails rather than
// being silently cut, which would make the message fail authentication for the
// wrong reason and hide the real cause.
func TestReadCappedRefusesTruncation(t *testing.T) {
	r := bytes.NewReader(make([]byte, MaxMessageLen+1))
	if _, err := ReadCapped(r); !errors.Is(err, ErrOversize) {
		t.Fatalf("want ErrOversize, got %v", err)
	}

	ok := bytes.NewReader(make([]byte, 100))
	if _, err := ReadCapped(ok); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCapped(bytes.NewReader(nil)); err == nil {
		t.Fatal("empty input must be rejected")
	}
}

func TestOversizeBodyRejectedOnWrite(t *testing.T) {
	var buf bytes.Buffer
	f := &Frame{Recipient: "alice", Body: make([]byte, MaxMessageLen+1)}
	if err := WriteFrame(&buf, f); !errors.Is(err, ErrOversize) {
		t.Fatalf("want ErrOversize, got %v", err)
	}
}
