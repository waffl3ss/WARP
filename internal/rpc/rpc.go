// Package rpc is the surface every WARP client speaks.
//
// The daemon owns the radios, the scheduler, the scope gate and the store; clients are thin.
// The REPL and the one-shot subcommands are both clients of this same surface - no
// functionality is REPL-only - so anything reachable interactively is scriptable.
//
// The transport is newline-delimited JSON-RPC 2.0 over a Unix domain socket. JSON-RPC rather
// than gRPC because it keeps the binary dependency-free and the wire format readable with
// `nc` when something is wrong on site at 2am.
package rpc

import (
	"encoding/json"
	"fmt"
)

// Version is the JSON-RPC version string.
const Version = "2.0"

// Request is a JSON-RPC request. A request with no ID is a notification and gets no response.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("%s (%d): %v", e.Message, e.Code, e.Data)
	}
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

// JSON-RPC error codes. The application range below -32000 is WARP's own.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603

	// CodeScopeDenied means the request was refused by the scope gate. It is distinct from a
	// generic internal error so a client can render it as an authorization decision rather
	// than a failure - a denial is a correct outcome, not a bug.
	CodeScopeDenied = -32000
	// CodeUnsatisfiable means no radio could serve a required role.
	CodeUnsatisfiable = -32001
	// CodeNotFound means the referenced job, BSSID or walkthrough does not exist.
	CodeNotFound = -32002
)

// EventMethod is the notification method the daemon uses to push asynchronous events.
//
// These are what land in REPL scrollback:
//
//	[+] PMKID  CORP-WIFI  a4:...:1f  ch6  → pmkid.22000
const EventMethod = "event"

// Event is an asynchronous notification from the daemon.
type Event struct {
	// Kind is the event type, e.g. "pmkid", "eapol", "bssid", "job", "radio".
	Kind string `json:"kind"`
	// Level is "info", "good" or "warn" - how the REPL should render it.
	Level string `json:"level,omitempty"`
	// Text is the preformatted operator-facing line.
	Text string `json:"text"`
	// Fields carries the structured form of the same information for scripted clients.
	Fields map[string]any `json:"fields,omitempty"`
}

// Event levels.
const (
	LevelInfo = "info"
	LevelGood = "good"
	LevelWarn = "warn"
)
