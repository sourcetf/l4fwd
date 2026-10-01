//go:build !windows

package netutil

import (
	"errors"
	"net"
	"time"
)

// GatedListener is only implemented on Windows; the stub keeps other platforms
// compiling.
type GatedListener struct{}

// ErrGatedUnsupported is returned off Windows.
var ErrGatedUnsupported = errors.New("gated listeners are only implemented on Windows")

// ListenGated always fails on non Windows platforms.
func ListenGated(string, int, int) (*GatedListener, error) { return nil, ErrGatedUnsupported }

// Addr is unsupported.
func (g *GatedListener) Addr() net.Addr { return nil }

// Accept is unsupported.
func (g *GatedListener) Accept(func() (net.Conn, error)) (net.Conn, error) {
	return nil, ErrGatedUnsupported
}

// Close is a no-op.
func (g *GatedListener) Close() error { return nil }

// SetDeadline is a no-op.
func (g *GatedListener) SetDeadline(time.Time) error { return nil }

// UpstreamOf is unsupported.
func UpstreamOf(net.Conn) net.Conn { return nil }
