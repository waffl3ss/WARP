package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// eventBuffer is how many asynchronous events a client will hold before dropping the oldest.
// Scrollback is a convenience; the store is the record.
const eventBuffer = 256

// Client is a connection to a running warpd.
//
// Both frontends - the REPL and the one-shot subcommands - use this. Clients are thin: they
// hold no engagement state and can disconnect and reconnect freely without affecting running
// jobs.
type Client struct {
	conn net.Conn
	enc  *json.Encoder

	mu      sync.Mutex
	pending map[string]chan Response
	nextID  atomic.Uint64

	events chan Event

	closeOnce sync.Once
	closed    chan struct{}
	readErr   error
}

// Dial connects to the daemon's Unix socket.
func Dial(path string) (*Client, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("rpc: connect to warpd at %s: %w (is the daemon running?)", path, err)
	}

	c := &Client{
		conn:    conn,
		enc:     json.NewEncoder(conn),
		pending: make(map[string]chan Response),
		events:  make(chan Event, eventBuffer),
		closed:  make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// Events returns the channel of asynchronous daemon events.
//
// The channel is closed when the connection ends. Events are dropped rather than blocking the
// reader if the consumer falls behind - a stalled REPL must not wedge the connection.
func (c *Client) Events() <-chan Event { return c.events }

// Call invokes a method and decodes the result into out, which may be nil.
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("rpc: marshal params for %s: %w", method, err)
		}
		raw = b
	}

	id := fmt.Sprintf("%d", c.nextID.Add(1))
	idJSON, _ := json.Marshal(id)

	ch := make(chan Response, 1)
	c.mu.Lock()
	c.pending[id] = ch
	err := c.enc.Encode(Request{JSONRPC: Version, ID: idJSON, Method: method, Params: raw})
	c.mu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("rpc: send %s: %w", method, err)
	}

	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()

	case <-c.closed:
		if c.readErr != nil {
			return fmt.Errorf("rpc: connection lost during %s: %w", method, c.readErr)
		}
		return fmt.Errorf("rpc: connection closed during %s", method)

	case resp := <-ch:
		if resp.Error != nil {
			return resp.Error
		}
		if out == nil || len(resp.Result) == 0 {
			return nil
		}
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("rpc: decode result of %s: %w", method, err)
		}
		return nil
	}
}

// Notify sends a request that expects no response.
func (c *Client) Notify(method string, params any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("rpc: marshal params for %s: %w", method, err)
		}
		raw = b
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(Request{JSONRPC: Version, Method: method, Params: raw})
}

// Close ends the connection. Running jobs on the daemon are unaffected.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.conn.Close()
	})
	return err
}

func (c *Client) readLoop() {
	defer func() {
		c.mu.Lock()
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
		close(c.closed)
		close(c.events)
	}()

	scanner := bufio.NewScanner(c.conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// A message with no ID is a server-initiated notification, not a response.
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			continue
		}

		if len(probe.ID) == 0 {
			if probe.Method == EventMethod {
				var ev Event
				if err := json.Unmarshal(probe.Params, &ev); err == nil {
					select {
					case c.events <- ev:
					default: // consumer is behind; drop rather than stall the connection
					}
				}
			}
			continue
		}

		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}
		var id string
		if err := json.Unmarshal(resp.ID, &id); err != nil {
			continue
		}

		c.mu.Lock()
		ch, ok := c.pending[id]
		delete(c.pending, id)
		c.mu.Unlock()
		if ok {
			ch <- resp
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		c.readErr = err
	}
}
