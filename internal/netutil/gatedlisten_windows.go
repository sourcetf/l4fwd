//go:build windows

package netutil

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// soConditionalAccept defers the handshake completion to WSAAccept's
	// callback, which is what lets a forwarder refuse a connection when the
	// target cannot be reached.
	soConditionalAccept = 0x3002
	cfAccept            = 0
	cfReject            = 1
)

var (
	ws2DLL        = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAAccept = ws2DLL.NewProc("WSAAccept")
)

// GatedListener is a TCP listener whose handshake is only completed after a
// caller supplied gate function succeeds. With it, a probe that merely performs
// a TCP connect (a "tcping" utility, a custom TCP client) learns whether the
// *target* port is reachable, not just whether the forwarder is running: when
// the gate fails the SYN is rejected instead of accepted.
//
// The gate must answer quickly. Two Windows behaviours make this a hard
// requirement rather than a preference:
//
//   - The kernel runs one condition callback at a time per listening socket, and
//     connections arriving meanwhile stay unacknowledged behind it.
//   - A client that does not get its handshake completed gives up after about a
//     second (Windows retransmits a few times and then fails the connect).
//
// So a gate that takes one target round trip per call means a burst of N
// connections costs N round trips, and everything past the first few SYNs *dies*
// with "connected party did not properly respond" even though the target is
// fine. Deferring the decision (CF_DEFER) does not help: the deferred connection
// keeps its place at the head of the queue and blocks the ones behind it.
//
// The listener therefore has to be fed an *answer*, not a question: the gate
// should decide from already-known information (a reachability cache) whenever
// it can. See the engine's probeTarget for how that is arranged.
type GatedListener struct {
	fd     windows.Handle
	laddr  net.Addr
	once   sync.Once
	closed chan struct{}
}

// gateResult carries the outcome of one gate call from the callback back to the
// worker owning that accept.
type gateResult struct {
	gate     func() (net.Conn, error)
	upstream net.Conn
	accepted bool
	err      error
}

// The callback is registered exactly once for the whole process and picks its
// work out of a table keyed by the integer handed to WSAAccept as
// dwCallbackData.
//
// Registering a closure per accept instead is fatal: syscall.NewCallback keys
// its table by function value, so every connection registered a fresh entry, and
// entry 2000 makes the runtime throw "too many callback functions" — a hard
// process crash. A forwarded port does that many connections in a few minutes of
// normal use.
var (
	gatesMu sync.Mutex
	gates   = map[uintptr]*gateResult{}
	gateKey uintptr
	gateCB  uintptr
	cbOnce  sync.Once
)

// gateCallback is the one WSAAccept condition function of this process. It must
// not be a closure: its address is what the runtime keys the registration by.
//
// The parameter list must match WSAAccept's condition function exactly in count
// and width (four register arguments followed by stack arguments on x64). The
// runtime builds the Go frame from the declared signature, so an extra or
// missing parameter makes dwCallbackData read past the frame and arrive as
// garbage — which shows up as "every connection is refused".
func gateCallback(_, _, _, _, _, _ uintptr, _ *uintptr, data uintptr) uintptr {
	gatesMu.Lock()
	res := gates[data]
	gatesMu.Unlock()
	if res == nil {
		// Unknown slot: refuse rather than accept into nowhere.
		return cfReject
	}
	conn, err := res.gate()
	res.upstream, res.err = conn, err
	if err != nil {
		return cfReject
	}
	// A nil upstream means "no answer yet, but forward anyway": the caller dials
	// the target itself once the client is connected. That keeps bursts moving
	// when the relay already knows the target was reachable moments ago.
	res.accepted = true
	return cfAccept
}

func callbackAddr() uintptr {
	cbOnce.Do(func() { gateCB = syscall.NewCallback(gateCallback) })
	return gateCB
}

// registerGate publishes a gate for the duration of one accept.
func registerGate(gate func() (net.Conn, error)) (uintptr, *gateResult) {
	res := &gateResult{gate: gate}
	gatesMu.Lock()
	gateKey++
	key := gateKey
	gates[key] = res
	gatesMu.Unlock()
	return key, res
}

func unregisterGate(key uintptr) {
	gatesMu.Lock()
	delete(gates, key)
	gatesMu.Unlock()
}

// ListenGated opens a TCP listener with SO_CONDITIONAL_ACCEPT enabled.
//
// A wildcard address binds an AF_INET6 socket with IPV6_V6ONLY disabled, so the
// gated listener serves IPv4 and IPv6 alike: Windows resolves "localhost" to ::1
// first, and a client that only finds an IPv4 socket would report the forwarder as
// unreachable.
func ListenGated(host string, port int, bufferKB int) (*GatedListener, error) {
	family := int32(windows.AF_INET6)
	bindV6 := net.IPv6unspecified
	bindV4 := net.IPv4zero
	specific := !IsWildcardHost(host)
	if specific {
		h := NormalizeHost(host)
		ip := net.ParseIP(h)
		if ip == nil {
			return nil, fmt.Errorf("listen address %q is not an IP", h)
		}
		if ip.To4() != nil {
			family = int32(windows.AF_INET)
			bindV4 = ip
		} else {
			bindV6 = ip
		}
	}

	// WSA_FLAG_OVERLAPPED (0x01) is required for the Go runtime poller to drive
	// the accepted sockets; sockets accepted from an overlapped listener inherit
	// the flag, and a non-overlapped socket aborts the connection as soon as it
	// is registered with the poller.
	const wsaFlagOverlapped = 0x01
	fd, err := windows.WSASocket(family, int32(windows.SOCK_STREAM), int32(windows.IPPROTO_TCP),
		nil, 0, wsaFlagOverlapped)
	if err != nil {
		return nil, fmt.Errorf("WSASocket: %w", err)
	}
	if err := windows.SetsockoptInt(fd, windows.SOL_SOCKET, soConditionalAccept, 1); err != nil {
		windows.Closesocket(fd)
		return nil, fmt.Errorf("SO_CONDITIONAL_ACCEPT: %w", err)
	}
	// A wildcard (dual-stack) bind does not report a conflict with an existing
	// IPv4 listener — the two sockets would quietly split the traffic — so the
	// IPv4 side is probed first, exactly as a plain TCP relay does.
	if IsWildcardHost(host) {
		if err := probePortFree("tcp4", port); err != nil {
			windows.Closesocket(fd)
			return nil, err
		}
	}
	// SO_REUSEADDR is what lets a restart bind a port that still has connections in
	// TIME_WAIT; without it a busy rule could refuse to start for minutes after a
	// restart. The cost is that Windows also allows a second *listener* on the same
	// port, so a wildcard bind is preceded by an explicit IPv4 probe (below) to
	// turn that silent sharing into a clear error.
	_ = windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	// Nagle off on the listening socket: accepted sockets inherit it, and a relay
	// must never hold a small write back waiting for a delayed ACK.
	_ = windows.SetsockoptInt(fd, windows.IPPROTO_TCP, windows.TCP_NODELAY, 1)
	// Socket buffers are inherited by accepted sockets too, which is what keeps a
	// bulk transfer from being limited to one 64 KiB window per connection.
	setSockbuf(uintptr(fd), bufferKB)
	if family == int32(windows.AF_INET6) {
		// Dual-stack: accept IPv4 connections on the same socket.
		if err := windows.SetsockoptInt(fd, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 0); err != nil {
			windows.Closesocket(fd)
			return nil, fmt.Errorf("IPV6_V6ONLY: %w", err)
		}
	}

	if family == int32(windows.AF_INET6) {
		v6 := bindV6.To16()
		var addr [16]byte
		copy(addr[:], v6)
		if err := windows.Bind(fd, &windows.SockaddrInet6{Port: port, Addr: addr}); err != nil {
			windows.Closesocket(fd)
			return nil, fmt.Errorf("bind %s: %w", HostPort(host, port), err)
		}
	} else {
		v4 := bindV4.To4()
		if err := windows.Bind(fd, &windows.SockaddrInet4{Port: port, Addr: [4]byte{v4[0], v4[1], v4[2], v4[3]}}); err != nil {
			windows.Closesocket(fd)
			return nil, fmt.Errorf("bind %s: %w", HostPort(host, port), err)
		}
	}
	if err := windows.Listen(fd, 128); err != nil {
		windows.Closesocket(fd)
		return nil, fmt.Errorf("listen %s: %w", HostPort(host, port), err)
	}
	gl := &GatedListener{fd: fd, closed: make(chan struct{})}
	gl.laddr = &net.TCPAddr{IP: bindV6, Port: port}
	return gl, nil
}

// Addr returns the listening address.
func (g *GatedListener) Addr() net.Addr { return g.laddr }

// Accept performs one gated accept: the gate decides whether the handshake
// completes, and any error is returned to the caller, which decides whether to
// keep serving (a refused connection is normal when the target is unreachable)
// or to stop (the listener was closed).
func (g *GatedListener) Accept(gate func() (net.Conn, error)) (net.Conn, error) {
	select {
	case <-g.closed:
		return nil, net.ErrClosed
	default:
	}
	client, err := g.acceptOnce(gate)
	if err != nil && errors.Is(err, errBlockingCancelled) {
		// Closing the listener interrupts a pending WSAAccept with this code.
		return nil, net.ErrClosed
	}
	return client, err
}

// errBlockingCancelled is what Winsock returns when a blocking call is
// interrupted because the socket was closed (WSAEINTR / WSAECANCELED).
var errBlockingCancelled = windows.WSAEINTR

func (g *GatedListener) acceptOnce(gate func() (net.Conn, error)) (net.Conn, error) {
	// The gate result belongs to this one accept call. Several workers park in
	// WSAAccept at once, and dwCallbackData carries the slot index (an integer,
	// so no Go pointer ever crosses into the kernel).
	key, res := registerGate(gate)
	defer unregisterGate(key)

	handle, err := callWSAAccept(g.fd, callbackAddr(), key)

	up, gerr := res.upstream, res.err
	switch {
	case err != nil:
		// WSAAccept failed (a non-zero callback answer reports as -1).
		if up != nil {
			_ = up.Close()
		}
		if gerr != nil {
			return nil, gerr
		}
		return nil, err
	case gerr != nil:
		_ = windows.Closesocket(handle)
		return nil, gerr
	}

	conn, cerr := handleToConn(handle)
	if cerr != nil {
		_ = windows.Closesocket(handle)
		if up != nil {
			_ = up.Close()
		}
		return nil, cerr
	}
	// The upstream travels with the client connection so the caller can pair
	// them; it is nil when the gate decided to forward without a probe.
	return &gatedConn{Conn: conn, upstream: up}, nil
}

// callWSAAccept performs one WSAAccept, letting the callback decide.
func callWSAAccept(fd windows.Handle, cb uintptr, data uintptr) (windows.Handle, error) {
	var addr windows.RawSockaddrAny
	addrLen := int32(unsafe.Sizeof(addr))
	r1, _, callErr := procWSAAccept.Call(
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		cb,
		data,
	)
	if int32(r1) == -1 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, errors.New("WSAAccept failed")
	}
	return windows.Handle(r1), nil
}

// handleToConn converts an accepted socket handle into a net.Conn.
//
// The handle is driven directly (see WinConn) instead of going through
// net.FileConn: adopting an accepted socket via the runtime poller aborts the
// connection on Windows.
func handleToConn(h windows.Handle) (net.Conn, error) {
	return NewWinConn(h)
}

// gatedConn carries the upstream connection the gate opened alongside the
// client connection.
type gatedConn struct {
	net.Conn
	upstream net.Conn
}

// Upstream returns the connection the gate established, if any.
func (g *gatedConn) Upstream() net.Conn { return g.upstream }

// Close closes both sides.
func (g *gatedConn) Close() error {
	err := g.Conn.Close()
	if g.upstream != nil {
		_ = g.upstream.Close()
	}
	return err
}

// Close stops the listener.
func (g *GatedListener) Close() error {
	var err error
	g.once.Do(func() {
		close(g.closed)
		err = windows.Closesocket(g.fd)
	})
	return err
}

// SetDeadline is a no-op kept for interface symmetry; the listener does not
// support deadlines.
func (g *GatedListener) SetDeadline(time.Time) error { return nil }

// UpstreamOf extracts the upstream connection created by the gate.
func UpstreamOf(c net.Conn) net.Conn {
	if gc, ok := c.(*gatedConn); ok {
		return gc.upstream
	}
	return nil
}
