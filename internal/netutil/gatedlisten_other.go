//go:build !windows

package netutil

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// GatedListener is a TCP listener whose connections are only handed to the caller
// after a gate function has approved them.
//
// On Linux and OpenBSD the kernel completes the TCP handshake before accept()
// returns, so — unlike Windows' SO_CONDITIONAL_ACCEPT — the gate cannot hold the
// handshake itself. It is still worth running: when the target is unreachable the
// connection is reset immediately (SO_LINGER 0), so a client that reads or writes
// learns about the failure at once instead of talking to a relay that has nowhere
// to send its bytes. A probe that only calls connect(), however, will have seen a
// successful handshake; that is a property of the platform, not of the relay, and
// the README documents it.
type GatedListener struct {
	ln     net.Listener
	closed chan struct{}
	once   sync.Once
}

// ListenGated opens a TCP listener that will be driven through Accept's gate.
func ListenGated(host string, port int, bufferKB int) (*GatedListener, error) {
	ln, err := ListenTCP(host, port, bufferKB)
	if err != nil {
		return nil, err
	}
	return &GatedListener{ln: ln, closed: make(chan struct{})}, nil
}

// Addr returns the listening address.
func (g *GatedListener) Addr() net.Addr { return g.ln.Addr() }

// Accept waits for a connection and then runs the gate. A gate error resets the
// client connection and is returned, exactly as a refused handshake is on
// Windows, so the engine's accept loop treats both platforms the same way.
func (g *GatedListener) Accept(gate func() (net.Conn, error)) (net.Conn, error) {
	select {
	case <-g.closed:
		return nil, net.ErrClosed
	default:
	}
	c, err := g.ln.Accept()
	if err != nil {
		return nil, err
	}
	if gate == nil {
		return &gatedConn{Conn: c}, nil
	}
	up, gerr := gate()
	if gerr != nil {
		resetConn(c)
		return nil, gerr
	}
	return &gatedConn{Conn: c, upstream: up}, nil
}

// resetConn closes a connection with a TCP RST instead of a FIN, so the peer
// stops waiting immediately.
func resetConn(c net.Conn) {
	if ls, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = ls.SetLinger(0)
	}
	_ = c.Close()
}

// Close stops the listener.
func (g *GatedListener) Close() error {
	var err error
	g.once.Do(func() {
		close(g.closed)
		err = g.ln.Close()
	})
	return err
}

// SetDeadline is a no-op kept for interface symmetry.
func (g *GatedListener) SetDeadline(time.Time) error { return nil }

// gatedConn carries the connection the gate opened for a client.
type gatedConn struct {
	net.Conn
	upstream net.Conn
}

// Upstream returns the connection the gate established, if any.
func (g *gatedConn) Upstream() net.Conn { return g.upstream }

// Underlying exposes the wrapped connection for code that needs the concrete
// type (buffer tuning, deadlines).
func (g *gatedConn) Underlying() net.Conn { return g.Conn }

// CloseWrite half closes the client side so EOF reaches the peer without tearing
// down the other direction.
func (g *gatedConn) CloseWrite() error {
	if wc, ok := g.Conn.(interface{ CloseWrite() error }); ok {
		return wc.CloseWrite()
	}
	return nil
}

// SetNoDelay, SetKeepAlive and SetKeepAlivePeriod forward to the wrapped TCP
// connection so the relay's tuning reaches the socket.
func (g *gatedConn) SetNoDelay(on bool) error {
	if tc, ok := g.Conn.(interface{ SetNoDelay(bool) error }); ok {
		return tc.SetNoDelay(on)
	}
	return nil
}

func (g *gatedConn) SetKeepAlive(on bool) error {
	if tc, ok := g.Conn.(interface{ SetKeepAlive(bool) error }); ok {
		return tc.SetKeepAlive(on)
	}
	return nil
}

func (g *gatedConn) SetKeepAlivePeriod(d time.Duration) error {
	if tc, ok := g.Conn.(interface{ SetKeepAlivePeriod(time.Duration) error }); ok {
		return tc.SetKeepAlivePeriod(d)
	}
	return nil
}

// SyscallConn exposes the underlying descriptor for socket buffer tuning.
func (g *gatedConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := g.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("gated connection does not expose a raw descriptor")
}

// Close closes both sides.
func (g *gatedConn) Close() error {
	err := g.Conn.Close()
	if g.upstream != nil {
		_ = g.upstream.Close()
	}
	return err
}

// UpstreamOf extracts the upstream connection created by the gate.
func UpstreamOf(c net.Conn) net.Conn {
	if gc, ok := c.(*gatedConn); ok {
		return gc.upstream
	}
	return nil
}
