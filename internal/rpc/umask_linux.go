package rpc

import "golang.org/x/sys/unix"

// syscallUmask sets the process umask and returns the previous value.
//
// It is used to close the window between net.Listen creating the socket inode and the
// subsequent Chmod. That window is short, but the socket is the interface that makes WARP
// transmit, so it should never be group- or world-writable even briefly.
//
// The umask is process-global, so this is called only during single-threaded startup.
func syscallUmask(mask int) int { return unix.Umask(mask) }
