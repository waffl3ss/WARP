package method

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestPipeConnReadHonoursDeadline: a Read on an empty pipe returns a timeout instead of blocking
// forever. This is what lets the TTLS Phase-2 peek safely check for maybe-absent front-loaded AVPs;
// before the deadline was honoured, SetReadDeadline was a no-op and this Read hung indefinitely.
func TestPipeConnReadHonoursDeadline(t *testing.T) {
	c := newPipeConn()
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	start := time.Now()
	n, err := c.Read(make([]byte, 16))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = (%d, %v), want (0, deadline exceeded)", n, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Read blocked %v - the deadline was ignored", elapsed)
	}
}

// TestPipeConnReadReturnsBufferedDataImmediately: data already fed (the TLS 1.3 front-load case) comes
// back at once, well before any deadline, so the peek captures it.
func TestPipeConnReadReturnsBufferedDataImmediately(t *testing.T) {
	c := newPipeConn()
	c.feed([]byte("avps"))
	c.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "avps" {
		t.Fatalf("Read = (%q, %v), want (avps, nil)", buf[:n], err)
	}
}
