//go:build windows

// Package netutil: raw IP socket helpers for Windows (WSARecvFrom/WSASendTo via x/sys).
package netutil

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SIO_RCVALL control codes.
const (
	sioRcvAll        = 0x98000001
	rcvAllOn  uint32 = 1
	rcvAllOff uint32 = 0
	// RCVALL_IPLEVEL keeps capture on a single interface, RCVALL_ON captures
	// every interface (both work in practice; IPLEVEL is what the API names).
	rcvAllIPLevel uint32 = 3
	// sioNonBlocking is FIONBIO, the Windows equivalent of O_NONBLOCK.
	sioNonBlocking = 0x8004667E
)

// RawSock offers packet level receive/send for an arbitrary IP protocol.
type RawSock struct {
	fd       windows.Handle
	proto    int
	bindIP   net.IP // nil means 0.0.0.0
	sniffing bool
	closeOne sync.Once
}

// RawSockOptions configures OpenRawSock.
type RawSockOptions struct {
	// Proto is the IP protocol number (1=ICMP, 47=GRE, 200=..., 255=raw).
	Proto int
	// BindIP binds the socket to one local address; nil binds 0.0.0.0.
	BindIP net.IP
	// Sniff enables SIO_RCVALL promiscuous capture. Requires a concrete BindIP.
	Sniff bool
	// HeaderIncl sets IP_HDRINCL so callers supply the whole IP header on send.
	HeaderIncl bool
	// SendOnly skips the receive side setup (no promiscuous mode).
	SendOnly bool
	// RcvBufBytes / SndBufBytes adjust SO_RCVBUF / SO_SNDBUF when > 0.
	RcvBufBytes int
	SndBufBytes int
}

// OpenRawSock creates a SOCK_RAW socket for the given protocol.
func OpenRawSock(opt RawSockOptions) (*RawSock, error) {
	family := windows.AF_INET
	fd, err := windows.WSASocket(int32(family), int32(windows.SOCK_RAW), int32(opt.Proto), nil, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("WSASocket(SOCK_RAW, proto=%d): %w", opt.Proto, err)
	}
	rs := &RawSock{fd: fd, proto: opt.Proto}
	fail := func(e error) (*RawSock, error) {
		windows.Closesocket(fd)
		return nil, e
	}

	if opt.HeaderIncl {
		if err := windows.SetsockoptInt(fd, windows.IPPROTO_IP, windows.IP_HDRINCL, 1); err != nil {
			return fail(fmt.Errorf("setsockopt IP_HDRINCL: %w", err))
		}
	}
	if opt.RcvBufBytes > 0 {
		// Best effort: Windows reports success for out of range values.
		_ = windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_RCVBUF, opt.RcvBufBytes)
	}
	if opt.SndBufBytes > 0 {
		_ = windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_SNDBUF, opt.SndBufBytes)
	}

	var bindTO *windows.SockaddrInet4
	if opt.BindIP != nil {
		ip4 := opt.BindIP.To4()
		if ip4 == nil {
			return fail(errors.New("bind IP must be IPv4"))
		}
		bindTO = &windows.SockaddrInet4{Port: 0, Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}}
		rs.bindIP = net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
	} else {
		bindTO = &windows.SockaddrInet4{Port: 0}
	}
	if err := windows.Bind(fd, bindTO); err != nil {
		return fail(fmt.Errorf("bind %v: %w", rs.bindIP, err))
	}
	// Raw sockets ignore SO_RCVTIMEO, so the socket is switched to non-blocking
	// mode and the capture loop polls instead. That also makes closing the
	// socket prompt.
	if err := rs.SetNonblocking(true); err != nil {
		return fail(fmt.Errorf("FIONBIO: %w", err))
	}

	if opt.Sniff && !opt.SendOnly {
		if rs.bindIP == nil {
			return fail(errors.New("SIO_RCVALL requires binding to a specific local IP address (Windows rejects it on 0.0.0.0)"))
		}
		if err := rs.setRcvAll(rcvAllIPLevel); err != nil {
			return fail(fmt.Errorf("SIO_RCVALL: %w", err))
		}
		rs.sniffing = true
	}
	return rs, nil
}

func (r *RawSock) setRcvAll(mode uint32) error {
	var out [4]byte
	var ret uint32
	return windows.WSAIoctl(r.fd, sioRcvAll, (*byte)(unsafe.Pointer(&mode)), 4, &out[0], 4, &ret, nil, 0)
}

// SetRcvAll switches promiscuous capture on or off at runtime.
func (r *RawSock) SetRcvAll(on bool) error {
	if r.bindIP == nil {
		return errors.New("SIO_RCVALL requires binding to a specific local IP address")
	}
	mode := rcvAllOff
	if on {
		mode = rcvAllIPLevel
	}
	if err := r.setRcvAll(mode); err != nil {
		return err
	}
	r.sniffing = on
	return nil
}

// Proto returns the protocol number of the socket.
func (r *RawSock) Proto() int { return r.proto }

// BindIP returns the bound local address (nil for 0.0.0.0).
func (r *RawSock) BindIP() net.IP { return r.bindIP }

// Sniffing reports whether promiscuous capture is active.
func (r *RawSock) Sniffing() bool { return r.sniffing }

// Close releases the socket.
func (r *RawSock) Close() error {
	var err error
	r.closeOne.Do(func() { err = windows.Closesocket(r.fd) })
	return err
}

// SetReadDeadline is not supported for raw sockets; callers use non-blocking
// reads with the socket's own timeout or a stop channel instead. It exists so
// the type satisfies a small interface used by the raw engine.

var (
	ws2_32DLL = windows.NewLazySystemDLL("ws2_32.dll")
	wsapollFn = ws2_32DLL.NewProc("WSAPoll")
)

// wsaPollFd mirrors the WSAPOLLFD structure.
type wsaPollFd struct {
	fd      windows.Handle
	events  int16
	revents int16
}

// Winsock poll event flags. These are *not* the POSIX values: POLLIN does not
// exist in Winsock (a readable socket reports POLLRDNORM, 0x0100), so passing
// 0x0001 makes WSAPoll fail with WSAEINVAL.
const (
	pollRDNorm = 0x0100
	pollRDBand = 0x0200
	pollWRNorm = 0x0010
	pollErr    = 0x0002
	pollHUp    = 0x0004
	pollNVal   = 0x0008
)

const pollReadable = pollRDNorm | pollRDBand

// sdSend is the "shutdown the send direction" argument for shutdown(); the
// constant is SHUT_WR on Windows and x/sys/windows does not export it.
const sdSend = 1

// WaitReadable blocks until the socket has data or the timeout elapses,
// reporting whether data is available. WSAPoll parks the thread inside the
// kernel, so an idle relay costs no CPU — unlike a non-blocking poll loop,
// which would burn a core on a machine with any background traffic.
func (r *RawSock) WaitReadable(timeoutMs int) (bool, error) {
	if timeoutMs < 0 {
		timeoutMs = 0
	}
	pfd := wsaPollFd{fd: r.fd, events: pollRDNorm}
	ret, _, callErr := wsapollFn.Call(uintptr(unsafe.Pointer(&pfd)), 1, uintptr(int32(timeoutMs)))
	n := int32(ret)
	if n > 0 {
		if pfd.revents&pollReadable != 0 {
			return true, nil
		}
		if pfd.revents&(pollErr|pollHUp|pollNVal) != 0 {
			// Let the caller attempt a read so it observes the real error.
			return true, nil
		}
		return false, nil
	}
	if n == 0 {
		return false, nil // timeout
	}
	if callErr != nil && callErr != syscall.Errno(0) {
		return false, callErr
	}
	return false, nil
}

// Receive reads one packet (including the IP header) into buf. On a
// non-blocking socket an empty queue reports WouldBlock so the caller can poll.
func (r *RawSock) Receive(buf []byte) (int, error) {
	var n uint32
	var flags uint32
	var from windows.RawSockaddrAny
	fromLen := int32(unsafe.Sizeof(from))
	wsabuf := &windows.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}
	err := windows.WSARecvFrom(r.fd, wsabuf, 1, &n, &flags, &from, &fromLen, nil, nil)
	if err != nil {
		if isWouldBlock(err) || isTimeout(err) {
			return 0, errWouldBlock
		}
		return 0, err
	}
	return int(n), nil
}

// Send transmits one packet; with HeaderIncl the buffer must contain the full
// IP header, otherwise dst is required so the stack can build the header.
func (r *RawSock) Send(pkt []byte, dst net.IP) error {
	var rsa windows.RawSockaddrAny
	rsaLen := int32(0)
	if dst != nil {
		ip4 := dst.To4()
		if ip4 == nil {
			return errors.New("destination must be IPv4")
		}
		p := (*rawSockaddrInet4)(unsafe.Pointer(&rsa))
		p.Family = windows.AF_INET
		p.Port = 0
		copy(p.Addr[:], ip4)
		rsaLen = int32(unsafe.Sizeof(rsa))
	}
	var sent uint32
	wsabuf := &windows.WSABuf{Len: uint32(len(pkt)), Buf: &pkt[0]}
	return windows.WSASendTo(r.fd, wsabuf, 1, &sent, 0, &rsa, rsaLen, nil, nil)
}

// SetNonblocking enables or disables non-blocking mode via FIONBIO.
func (r *RawSock) SetNonblocking(on bool) error {
	var mode uint32
	if on {
		mode = 1
	}
	var ret uint32
	return windows.WSAIoctl(r.fd, sioNonBlocking, (*byte)(unsafe.Pointer(&mode)), 4, nil, 0, &ret, nil, 0)
}

type rawSockaddrInet4 struct {
	Family int16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

var errWouldBlock = errors.New("raw socket: would block")

func isWouldBlock(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.WSAEWOULDBLOCK) || errors.Is(err, syscall.EWOULDBLOCK)
}

// isTimeout reports whether err is the socket receive timeout firing, which
// Windows reports as WSAETIMEDOUT.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.WSAETIMEDOUT) || errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.EAGAIN)
}

// WouldBlock reports whether err indicates a temporarily empty receive queue.
func WouldBlock(err error) bool { return errors.Is(err, errWouldBlock) }

// ReceivePacket is Receive with a slice result, so the relay's hot path can use
// the captured bytes in place. Windows raw sockets deliver the IP packet at the
// start of the buffer, so the slice is just buf[:n].
func (r *RawSock) ReceivePacket(buf []byte) ([]byte, error) {
	n, err := r.Receive(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// RawCaptureLoop reads packets until stop is closed, invoking fn for each.
// It blocks in WSAPoll between packets so an idle socket costs no CPU.
func (r *RawSock) RawCaptureLoop(buf []byte, stop <-chan struct{}, fn func(pkt []byte) error) error {
	if len(buf) < 2048 {
		buf = make([]byte, 65535)
	}
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		ready, err := r.WaitReadable(100)
		if err != nil {
			return err
		}
		if !ready {
			continue
		}
		for i := 0; i < 64; i++ {
			n, err := r.Receive(buf)
			if err != nil {
				if WouldBlock(err) {
					break
				}
				return err
			}
			if n <= 0 {
				continue
			}
			if err := fn(buf[:n]); err != nil {
				return err
			}
		}
	}
}

// FD exposes the underlying socket handle so a caller can wait on many sockets
// with one WSAPoll call instead of parking one thread per socket.
func (r *RawSock) FD() uintptr { return uintptr(r.fd) }

// PollOne describes one socket to wait on.
type PollOne struct {
	FD     uintptr
	Events int16
}

// PollReady parks until any of the sockets has data (or the timeout elapses) and
// returns the indices that are readable.
//
// Waiting on all the sockets of an "all protocols" rule with one call is what
// makes an idle relay cheap: one WSAPoll costs a few microseconds, so 250
// separate WSAPoll calls per round cost ~250× more than one call covering all of
// them.
func PollReady(socks []PollOne, timeoutMs int) ([]int, error) {
	if len(socks) == 0 {
		return nil, nil
	}
	pfds := make([]wsaPollFd, len(socks))
	for i, s := range socks {
		events := s.Events
		if events == 0 {
			events = pollRDNorm
		}
		pfds[i] = wsaPollFd{fd: windows.Handle(s.FD), events: events}
	}
	for {
		ret, _, callErr := wsapollFn.Call(uintptr(unsafe.Pointer(&pfds[0])), uintptr(len(pfds)), uintptr(int32(timeoutMs)))
		n := int32(ret)
		if n < 0 {
			if callErr != nil && callErr != syscall.Errno(0) {
				return nil, callErr
			}
			return nil, errors.New("WSAPoll failed")
		}
		if n == 0 {
			return nil, nil
		}
		var ready []int
		for i := range pfds {
			rev := pfds[i].revents
			if rev == 0 {
				continue
			}
			// A closed socket reports POLLNVAL: hand it to the caller so it can
			// notice its own shutdown instead of spinning here.
			if rev&(pollReadable|pollErr|pollHUp|pollNVal) != 0 {
				ready = append(ready, i)
			}
			pfds[i].revents = 0
		}
		if len(ready) == 0 {
			return nil, nil
		}
		return ready, nil
	}
}
