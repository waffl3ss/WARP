package method

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// pipeConn is a net.Conn whose two directions are in-memory buffers.
//
// crypto/tls wants a net.Conn, but EAP carries TLS records inside RADIUS attributes rather
// than over a socket. Rather than reimplement TLS, WARP hands crypto/tls one end of this pipe
// and shuttles the bytes in and out as EAP-TLS fragments - so the whole TLS implementation is
// the standard library's, which is exactly where that responsibility belongs.
//
// net.Pipe is not usable here: it is synchronous and unbuffered, so a TLS write with nobody
// reading deadlocks the handshake.
type pipeConn struct {
	mu   sync.Mutex
	cond *sync.Cond

	// inbound holds bytes received from the supplicant, waiting to be read by crypto/tls.
	inbound []byte
	// outbound holds bytes crypto/tls has written, waiting to be fragmented out.
	outbound []byte

	// readWaiting is set while the TLS goroutine is blocked wanting more bytes.
	//
	// This is what makes driving the handshake deterministic: a round is complete when TLS
	// has produced output and then gone back to waiting for input, which is precisely the
	// point at which an EAP request should be sent.
	readWaiting bool

	// readDeadline bounds a blocking Read. It exists so ReadApplication can safely *peek* for data
	// that may not have arrived yet (a TLS 1.3 client front-loads its first application data with its
	// Finished, a TLS 1.2 client does not) without blocking forever - without this, SetReadDeadline
	// was a no-op and a Read with an empty inbound buffer waited on the condition variable for good.
	readDeadline time.Time

	closed bool
	err    error
}

func newPipeConn() *pipeConn {
	c := &pipeConn{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Read implements net.Conn, blocking until bytes arrive from the supplicant, the pipe closes, or a
// read deadline (if set) elapses.
func (c *pipeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// A read deadline is honoured with a timer that wakes the condition variable, since cond.Wait
	// has no timeout of its own. Without this a Read on an empty buffer blocks forever.
	var timer *time.Timer
	if !c.readDeadline.IsZero() {
		if d := time.Until(c.readDeadline); d > 0 {
			timer = time.AfterFunc(d, func() {
				c.mu.Lock()
				c.cond.Broadcast()
				c.mu.Unlock()
			})
		}
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for len(c.inbound) == 0 && !c.closed {
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.readWaiting = false
			return 0, os.ErrDeadlineExceeded
		}
		c.readWaiting = true
		c.cond.Broadcast()
		c.cond.Wait()
	}
	c.readWaiting = false

	if len(c.inbound) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		return 0, io.EOF
	}

	n := copy(p, c.inbound)
	c.inbound = c.inbound[n:]
	return n, nil
}

// Write implements net.Conn, buffering bytes for the next outbound fragment.
func (c *pipeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}
	c.outbound = append(c.outbound, p...)
	c.cond.Broadcast()
	return len(p), nil
}

// Close implements net.Conn.
func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	c.cond.Broadcast()
	return nil
}

// feed queues bytes received from the supplicant.
func (c *pipeConn) feed(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.inbound = append(c.inbound, b...)
	c.cond.Broadcast()
}

// takeOutbound removes and returns everything crypto/tls has written.
func (c *pipeConn) takeOutbound() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := c.outbound
	c.outbound = nil
	return out
}

// fail records a terminal error and wakes any blocked reader.
func (c *pipeConn) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.err == nil {
		c.err = err
	}
	c.closed = true
	c.cond.Broadcast()
}

// net.Conn boilerplate. Deadlines are meaningless for an in-memory pipe driven by EAP
// round-trips; the RADIUS session timeout bounds the exchange instead.
func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr{} }
func (c *pipeConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline bounds a blocking Read. crypto/tls sets this before every Read; it used to be a
// no-op (fine while a payload was always fed first, hanging otherwise), and honouring it is what lets
// ReadApplication peek for maybe-absent data without blocking forever.
func (c *pipeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	c.cond.Broadcast()
	return nil
}
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "eap" }
func (pipeAddr) String() string  { return "eap-tls-pipe" }

// TLSSession drives a TLS handshake over EAP.
//
// The handshake's completion state is guarded by the pipe's mutex - the same one the
// condition variable uses - rather than by a channel alone. A waiter blocked in cond.Wait()
// must be woken by the same critical section that records the result, or a handshake that
// completes without writing any further bytes leaves the waiter asleep until a watchdog
// fires.
type TLSSession struct {
	conn *pipeConn
	tls  *tls.Conn

	// handshakeDone is closed for external observers; hsDone and hsErr are the
	// mutex-guarded state Exchange actually consults.
	handshakeDone chan struct{}
	hsDone        bool
	hsErr         error

	once sync.Once
}

// NewTLSServer starts a TLS server handshake over an EAP transport.
//
// The certificate presented here is the mimic: what the supplicant does with it - accept it,
// reject it, or prompt the user - is the finding the whole enterprise module exists to
// produce.
func NewTLSServer(cfg *tls.Config) *TLSSession {
	return newTLSSession(func(c *pipeConn) *tls.Conn { return tls.Server(c, cfg) })
}

// NewTLSClient starts a TLS *client* handshake over an EAP transport.
//
// The mirror image of NewTLSServer, and the other half of the enterprise module: this is the
// side that harvests. WARP associates to the target network as a station, answers its EAP
// identity request, and runs a TLS client handshake far enough to read the certificate the
// RADIUS server presents - then abandons it. Nothing is authenticated and no credential is
// sent, because the harvesting supplicant has none.
func NewTLSClient(cfg *tls.Config) *TLSSession {
	return newTLSSession(func(c *pipeConn) *tls.Conn { return tls.Client(c, cfg) })
}

func newTLSSession(build func(*pipeConn) *tls.Conn) *TLSSession {
	conn := newPipeConn()
	s := &TLSSession{
		conn:          conn,
		tls:           build(conn),
		handshakeDone: make(chan struct{}),
	}

	// The handshake runs on its own goroutine, blocking on Read until EAP delivers more
	// bytes. That inversion is what lets the standard library's TLS implementation drive a
	// protocol it knows nothing about.
	go func() {
		err := s.tls.Handshake()

		// Record the result and wake any waiter in the same critical section. Broadcasting
		// separately from recording would let a waiter observe "not done yet" and go back to
		// sleep having already consumed its wake-up.
		conn.mu.Lock()
		s.hsDone = true
		s.hsErr = err
		conn.cond.Broadcast()
		conn.mu.Unlock()

		if err != nil {
			conn.fail(err)
		}
		close(s.handshakeDone)
	}()

	return s
}

// HandshakeComplete reports whether the TLS handshake has finished successfully.
func (s *TLSSession) HandshakeComplete() bool {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	return s.hsDone && s.hsErr == nil
}

// HandshakeError returns the handshake failure, if any.
//
// A rejected certificate arrives here. That is a *pass* for the client and must be recorded
// as one: the tool measures supplicant configuration hygiene, and a supplicant that refuses
// an untrusted server is correctly configured.
func (s *TLSSession) HandshakeError() error {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	return s.hsErr
}

// ConnectionState exposes the negotiated TLS state, for MPPE key derivation and for recording
// what was negotiated.
func (s *TLSSession) ConnectionState() tls.ConnectionState { return s.tls.ConnectionState() }

// ErrHandshakeTimeout is returned when TLS produced neither output nor a result in time.
var ErrHandshakeTimeout = errors.New("method: TLS handshake stalled")

// Exchange feeds inbound TLS bytes and returns whatever TLS wants to send back.
//
// It returns once TLS has produced output and gone back to waiting for input, or once the
// handshake completes or fails. Waiting for the reader to block, rather than sleeping for a
// fixed interval, is what makes this deterministic: it returns exactly one EAP round's worth
// of bytes, no more and no less.
func (s *TLSSession) Exchange(in []byte, timeout time.Duration) ([]byte, error) {
	if len(in) > 0 {
		s.conn.feed(in)
	}

	deadline := time.Now().Add(timeout)
	done := make(chan struct{})

	// A watchdog wakes the condition variable so a stalled handshake cannot block forever.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-t.C:
			s.conn.mu.Lock()
			s.conn.cond.Broadcast()
			s.conn.mu.Unlock()
		case <-stop:
		case <-done:
		}
	}()

	s.conn.mu.Lock()
	for {
		hasOutput := len(s.conn.outbound) > 0
		waiting := s.conn.readWaiting
		closed := s.conn.closed
		finished := s.hsDone

		// A round is complete when TLS has written something and is back to waiting for more
		// input, or when the handshake reached a terminal state.
		if (hasOutput && (waiting || finished)) || closed || finished {
			break
		}
		if time.Now().After(deadline) {
			s.conn.mu.Unlock()
			close(done)
			if out := s.conn.takeOutbound(); len(out) > 0 {
				return out, nil
			}
			return nil, ErrHandshakeTimeout
		}
		s.conn.cond.Wait()
	}
	s.conn.mu.Unlock()
	close(done)

	out := s.conn.takeOutbound()

	if err := s.HandshakeError(); err != nil {
		// Any bytes TLS produced before failing are still worth sending: they usually carry
		// the alert that tells the supplicant why, which is what appears in its logs.
		return out, fmt.Errorf("method: TLS handshake failed: %w", err)
	}
	return out, nil
}

// WriteApplication encrypts application data into the TLS tunnel and returns the records to
// send. Used to carry PEAP's inner EAP conversation.
func (s *TLSSession) WriteApplication(b []byte, timeout time.Duration) ([]byte, error) {
	if !s.HandshakeComplete() {
		return nil, errors.New("method: cannot write application data before the handshake completes")
	}
	if _, err := s.tls.Write(b); err != nil {
		return nil, fmt.Errorf("method: write into the TLS tunnel: %w", err)
	}
	return s.conn.takeOutbound(), nil
}

// ReadApplication feeds inbound TLS records and returns decrypted application data.
func (s *TLSSession) ReadApplication(in []byte, timeout time.Duration) ([]byte, error) {
	if !s.HandshakeComplete() {
		return nil, errors.New("method: cannot read application data before the handshake completes")
	}
	if len(in) > 0 {
		s.conn.feed(in)
	}

	// The tunnel carries one inner EAP packet per round, comfortably under this bound.
	buf := make([]byte, 4096)
	s.tls.SetReadDeadline(time.Now().Add(timeout))
	n, err := s.tls.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("method: read from the TLS tunnel: %w", err)
	}
	return buf[:n], nil
}

// ExportKeyingMaterial derives MPPE keys from the TLS session.
//
// Only needed for the optional accept path, where WARP returns Access-Accept so a client
// completes the association - hostile-portal work. It is off by default: the default is
// Access-Reject, so the supplicant sees a failed login and is not placed on a network it
// should not be on.
func (s *TLSSession) ExportKeyingMaterial(label string, length int) ([]byte, error) {
	if !s.HandshakeComplete() {
		return nil, errors.New("method: cannot export keying material before the handshake completes")
	}
	state := s.tls.ConnectionState()
	km, err := state.ExportKeyingMaterial(label, nil, length)
	if err != nil {
		return nil, fmt.Errorf("method: export keying material: %w", err)
	}
	return km, nil
}

// Close tears the session down.
func (s *TLSSession) Close() error {
	var err error
	s.once.Do(func() {
		err = s.conn.Close()
	})
	return err
}
