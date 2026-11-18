// Package shadowlemonprotocol implements the ShadowLemon V0.2 (wire version 4)
// handshake, reliable session layer (ARQ/CUBIC), UDP routing envelope and mux
// glue. It mirrors the authoritative Rust crates shadowlemon-protocol and
// shadowlemon-wire so that Go peers interoperate byte-for-byte with Rust peers.
package shadowlemonprotocol

import "errors"

var (
	ErrClosed          = errors.New("shadowlemon: closed")
	ErrTimeout         = errors.New("shadowlemon: timeout")
	ErrNoCommonSuite   = errors.New("shadowlemon: no common cipher suite")
	ErrAuthentication  = errors.New("shadowlemon: authentication failed")
	ErrMalformed       = errors.New("shadowlemon: malformed message")
	ErrVersion         = errors.New("shadowlemon: unsupported protocol version")
	ErrReplay          = errors.New("shadowlemon: replayed segment")
	ErrBackpressure    = errors.New("shadowlemon: send queue is full")
	ErrTooManyRetries  = errors.New("shadowlemon: too many retransmissions")
	ErrWrongDirection  = errors.New("shadowlemon: wrong direction for protocol type")
	ErrSessionMismatch = errors.New("shadowlemon: session id mismatch")
)
