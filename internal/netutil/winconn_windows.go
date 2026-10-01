//go:build windows

package netutil

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WinConn adapts a connected Winsock socket to net.Conn.
//
// A socket produced by WSAAccept cannot reliably be handed to net.FileConn: the
// adoption duplicates the handle through WSADuplicateSocket and the runtime
// poller then tears the connection down ("established connection was aborted by
// the software in your host machine"). Driving the socket directly with
// WSARecv/WSASend and WSAPoll avoids that, and it keeps half close working,
// which the relay needs to propagate EOF in one direction only.
type WinConn struct {
	fd windows.Handle

	closeOnce sync.Once
	closeErr  error

	mu      sync.Mutex
	readBy  time.Time
	writeBy time.Time
}

// NewWinConn wraps a connected socket handle.
//
// Nagle is switched off here rather than at the call site: the relay's usual
// "if tc, ok := conn.(*net.TCPConn)" assertion never matches a WinConn, so the
// accepted client socket would keep Nagle enabled. With Nagle on, a small write
// whose predecessor is still unacknowledged is held back until the peer's
// delayed ACK or the next segment — tens of milliseconds added to every
// interactive round trip, on top of the other side of the relay.
func NewWinConn(fd windows.Handle) (*WinConn, error) {
	c := &WinConn{fd: fd}
	if err := c.SetNonblocking(true); err != nil {
		_ = windows.Closesocket(fd)
		return nil, err
	}
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAlive(true)
	return c, nil
}

// SetNonblocking toggles FIONBIO so reads and writes can be polled.
func (c *WinConn) SetNonblocking(on bool) error {
	var mode uint32
	if on {
		mode = 1
	}
	var ret uint32
	return windows.WSAIoctl(c.fd, sioNonBlocking, (*byte)(unsafe.Pointer(&mode)), 4, nil, 0, &ret, nil, 0)
}

// SetNoDelay controls Nagle's algorithm.
func (c *WinConn) SetNoDelay(on bool) error {
	v := 0
	if on {
		v = 1
	}
	return windows.SetsockoptInt(c.fd, windows.IPPROTO_TCP, windows.TCP_NODELAY, v)
}

// NoDelayEnabled reports whether Nagle is currently off, which the tests use to
// assert the wrapper configures the socket the way a relay needs.
func (c *WinConn) NoDelayEnabled() bool {
	v, err := windows.GetsockoptInt(c.fd, windows.IPPROTO_TCP, windows.TCP_NODELAY)
	return err == nil && v != 0
}

// SetKeepAlive enables keepalive probes.
func (c *WinConn) SetKeepAlive(on bool) error {
	v := 0
	if on {
		v = 1
	}
	return windows.SetsockoptInt(c.fd, windows.SOL_SOCKET, windows.SO_KEEPALIVE, v)
}

// LocalAddr reports the local endpoint.
func (c *WinConn) LocalAddr() net.Addr { return sockaddrAddr(mustSockname(c.fd)) }

// RemoteAddr reports the peer endpoint.
func (c *WinConn) RemoteAddr() net.Addr { return sockaddrAddr(mustPeername(c.fd)) }

func sockaddrAddr(sa *windows.SockaddrInet4) net.Addr {
	if sa == nil {
		return nil
	}
	return &net.TCPAddr{IP: net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]), Port: sa.Port}
}

func mustSockname(fd windows.Handle) *windows.SockaddrInet4 {
	if sa, err := windows.Getsockname(fd); err == nil {
		if v4, ok := sa.(*windows.SockaddrInet4); ok {
			return v4
		}
	}
	return nil
}

func mustPeername(fd windows.Handle) *windows.SockaddrInet4 {
	if sa, err := windows.Getpeername(fd); err == nil {
		if v4, ok := sa.(*windows.SockaddrInet4); ok {
			return v4
		}
	}
	return nil
}

// SetDeadline sets both deadlines.
func (c *WinConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readBy, c.writeBy = t, t
	c.mu.Unlock()
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *WinConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readBy = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *WinConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeBy = t
	c.mu.Unlock()
	return nil
}

// timeoutError implements net.Error for deadline expiries.
type timeoutError struct{ op string }

func (e *timeoutError) Error() string   { return "winconn: " + e.op + " deadline exceeded" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// pollInfinite tells WSAPoll to wait without a timeout.
const pollInfinite = -1

// pollSliceMs bounds how long a single WSAPoll parks when the caller set no
// deadline. Waiting forever would leave Close unobserved until the peer speaks;
// re-polling every slice keeps an idle connection at zero CPU while still
// noticing a closed socket within a fraction of a second.
const pollSliceMs = 250

// pollTimeout clamps an "infinite" poll to one slice.
func pollTimeout(timeoutMs int) int {
	if timeoutMs == pollInfinite {
		return pollSliceMs
	}
	return timeoutMs
}

func (c *WinConn) readTimeout() (int, bool) {
	c.mu.Lock()
	d := c.readBy
	c.mu.Unlock()
	return deadlineToPollTimeout(d)
}

func (c *WinConn) writeTimeout() (int, bool) {
	c.mu.Lock()
	d := c.writeBy
	c.mu.Unlock()
	return deadlineToPollTimeout(d)
}

func deadlineToPollTimeout(d time.Time) (int, bool) {
	if d.IsZero() {
		return pollInfinite, false
	}
	remaining := time.Until(d)
	if remaining <= 0 {
		return 0, true
	}
	ms := int(remaining / time.Millisecond)
	if ms <= 0 {
		ms = 1
	}
	return ms, false
}

// Read implements net.Conn.
//
// The receive comes first: on a socket that has data queued — the normal state
// for a relay, whose peer is usually waiting to write — it succeeds immediately
// and the poll is skipped, which halves the syscalls per read. When the queue is
// empty the read has to park in WSAPoll rather than retry, or every idle
// connection would spin a core; the wait is bounded (see pollSliceMs) so a
// closed socket is still noticed promptly.
func (c *WinConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	wb := &windows.WSABuf{Len: uint32(len(p)), Buf: &p[0]}
	for {
		var n uint32
		var flags uint32
		err := windows.WSARecv(c.fd, wb, 1, &n, &flags, nil, nil)
		if err == nil {
			if n == 0 {
				// A zero length receive means the peer closed its side.
				return 0, io.EOF
			}
			return int(n), nil
		}
		if !isWouldBlock(err) {
			return 0, err
		}
		// Nothing queued: wait for the socket instead of retrying in a loop.
		timeoutMs, expired := c.readTimeout()
		if expired {
			return 0, &timeoutError{op: "read"}
		}
		if _, werr := c.wait(pollRDNorm, pollTimeout(timeoutMs)); werr != nil {
			return 0, werr
		}
	}
}

// Write implements net.Conn.
func (c *WinConn) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		timeoutMs, expired := c.writeTimeout()
		if expired {
			return total, &timeoutError{op: "write"}
		}
		var n uint32
		wb := &windows.WSABuf{Len: uint32(len(p) - total), Buf: &p[total]}
		err := windows.WSASend(c.fd, wb, 1, &n, 0, nil, nil)
		if err == nil {
			total += int(n)
			continue
		}
		if isWouldBlock(err) {
			// A full send buffer has to be waited out; retrying immediately would
			// spin a core here instead.
			if _, perr := c.wait(pollWRNorm, pollTimeout(timeoutMs)); perr != nil {
				return total, perr
			}
			continue
		}
		return total, err
	}
	return total, nil
}

// CloseWrite half closes the connection so the peer sees EOF while the read
// side stays open.
func (c *WinConn) CloseWrite() error {
	return windows.Shutdown(c.fd, sdSend)
}

// Close closes the socket.
func (c *WinConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = windows.Closesocket(c.fd)
	})
	return c.closeErr
}

// wait blocks until the socket reports the requested event or the timeout
// elapses.
func (c *WinConn) wait(events int16, timeoutMs int) (bool, error) {
	pfd := wsaPollFd{fd: c.fd, events: events}
	ret, _, callErr := wsapollFn.Call(uintptr(unsafe.Pointer(&pfd)), 1, uintptr(int32(timeoutMs)))
	switch n := int32(ret); {
	case n > 0:
		if pfd.revents&(events|pollReadable|pollWRNorm) != 0 {
			return true, nil
		}
		if pfd.revents&(pollErr|pollHUp|pollNVal) != 0 {
			// Report readiness so the caller's next call surfaces the real error.
			return true, nil
		}
		return false, nil
	case n == 0:
		return false, nil
	default:
		if callErr != nil && callErr != syscall.Errno(0) {
			return false, callErr
		}
		return false, errors.New("WSAPoll failed")
	}
}

// Compile time assertion that WinConn satisfies the interfaces the relay uses.
var (
	_ net.Conn = (*WinConn)(nil)
	_ interface {
		CloseWrite() error
	} = (*WinConn)(nil)
)

// zoneName renders a scope id the way net.TCPAddr expects it.
func zoneName(scope uint32) string {
	if scope == 0 {
		return ""
	}
	return fmt.Sprintf("%d", scope)
}
