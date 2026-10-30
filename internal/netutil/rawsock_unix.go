//go:build linux || openbsd

// Package netutil: raw IP socket helpers for Linux and OpenBSD.
//
// Unlike Windows, both systems let a raw socket carry any protocol number the
// process has privilege for, and both deliver a copy of every matching packet
// addressed to the host. Promiscuous capture needs another socket family on each
// (AF_PACKET on Linux, /dev/bpf on OpenBSD); those live in files of their own.
package netutil

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// RawSock offers packet level receive/send for an arbitrary IP protocol.
type RawSock struct {
	fd       int
	proto    int
	bindIP   net.IP
	sniffing bool
	kind     rawSockKind
	// l2Skip is how many link layer bytes precede the IP header in a captured
	// frame. Zero for a raw IP socket.
	l2Skip int
	// ifName is the interface a promiscuous capture is attached to.
	ifName   string
	closeOne sync.Once

	// BPF capture state (OpenBSD only): records read but not yet returned.
	bpfPending []byte
	bpfBuf     []byte
}

type rawSockKind uint8

const (
	rawKindIP     rawSockKind = iota // AF_INET SOCK_RAW, receives packets addressed to us
	rawKindPacket                    // AF_PACKET (Linux promiscuous capture)
	rawKindBPF                       // /dev/bpf (OpenBSD promiscuous capture)
)

// RawSockOptions configures OpenRawSock.
type RawSockOptions struct {
	// Proto is the IP protocol number (1=ICMP, 47=GRE, 200=..., 255=raw).
	Proto int
	// BindIP binds the socket to one local address; nil binds 0.0.0.0.
	BindIP net.IP
	// Sniff enables promiscuous capture. Requires privilege; when BindIP is nil
	// the capture is attached to the interface carrying the default route.
	Sniff bool
	// HeaderIncl sets IP_HDRINCL so callers supply the whole IP header on send.
	HeaderIncl bool
	// SendOnly skips the receive side setup (no promiscuous mode).
	SendOnly bool
	// RcvBufBytes / SndBufBytes adjust SO_RCVBUF / SO_SNDBUF when > 0.
	RcvBufBytes int
	SndBufBytes int
}

// OpenRawSock creates the socket the options describe.
func OpenRawSock(opt RawSockOptions) (*RawSock, error) {
	if opt.Proto < 0 || opt.Proto > 255 {
		return nil, fmt.Errorf("protocol number %d out of range", opt.Proto)
	}
	if opt.Sniff && !opt.SendOnly {
		return openSniffSock(opt)
	}
	return openRawIPSock(opt)
}

// openRawIPSock opens an AF_INET SOCK_RAW socket.
func openRawIPSock(opt RawSockOptions) (*RawSock, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, opt.Proto)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_INET, SOCK_RAW, proto=%d): %w%s", opt.Proto, err, privilegeHint(err))
	}
	unix.CloseOnExec(fd)
	rs := &RawSock{fd: fd, proto: opt.Proto, kind: rawKindIP}
	fail := func(e error) (*RawSock, error) {
		_ = unix.Close(fd)
		return nil, e
	}

	if opt.HeaderIncl {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			return fail(fmt.Errorf("setsockopt IP_HDRINCL: %w", err))
		}
	}
	setSockbuf(uintptr(fd), opt.RcvBufBytes>>10)
	if opt.SndBufBytes > 0 {
		// setSockbuf sizes both directions; the send side asks separately so the
		// two values stay independent for callers that want that.
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, opt.SndBufBytes)
	}

	var sa unix.Sockaddr = &unix.SockaddrInet4{}
	if opt.BindIP != nil {
		ip4 := opt.BindIP.To4()
		if ip4 == nil {
			return fail(errors.New("bind IP must be IPv4"))
		}
		var addr [4]byte
		copy(addr[:], ip4)
		sa = &unix.SockaddrInet4{Addr: addr}
		rs.bindIP = net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
	}
	if err := unix.Bind(fd, sa); err != nil {
		return fail(fmt.Errorf("bind %v: %w%s", rs.bindIP, err, privilegeHint(err)))
	}
	// Non-blocking plus poll is what lets a closed socket be noticed and what
	// keeps an idle relay from parking a thread per captured protocol.
	if err := unix.SetNonblock(fd, true); err != nil {
		return fail(fmt.Errorf("set non-blocking: %w", err))
	}
	return rs, nil
}

// privilegeHint turns the opaque EPERM/EACCES a raw socket returns into an
// actionable message. Both systems need root (Linux: CAP_NET_RAW is enough).
func privilegeHint(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return "（需要 root 或 CAP_NET_RAW 权限）"
	}
	return ""
}

// Proto returns the protocol number of the socket.
func (r *RawSock) Proto() int { return r.proto }

// BindIP returns the bound local address (nil for 0.0.0.0).
func (r *RawSock) BindIP() net.IP { return r.bindIP }

// Sniffing reports whether promiscuous capture is active.
func (r *RawSock) Sniffing() bool { return r.sniffing }

// Interface returns the interface a promiscuous capture reads, if any.
func (r *RawSock) Interface() string { return r.ifName }

// Close releases the socket.
func (r *RawSock) Close() error {
	var err error
	r.closeOne.Do(func() { err = unix.Close(r.fd) })
	return err
}

// Send transmits one packet. With HeaderIncl the buffer carries the full IP
// header; a promiscuous capture socket is receive-only.
func (r *RawSock) Send(pkt []byte, dst net.IP) error {
	if r.kind != rawKindIP {
		return errors.New("capture socket cannot send packets")
	}
	var sa unix.Sockaddr
	if dst != nil {
		ip4 := dst.To4()
		if ip4 == nil {
			return errors.New("destination must be IPv4")
		}
		var addr [4]byte
		copy(addr[:], ip4)
		sa = &unix.SockaddrInet4{Addr: addr}
	}
	for {
		err := unix.Sendto(r.fd, pkt, 0, sa)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("sendto %v: %w%s", dst, err, privilegeHint(err))
		}
		return nil
	}
}

// Receive reads one packet into buf, including the IP header.
func (r *RawSock) Receive(buf []byte) (int, error) {
	if r.kind != rawKindIP {
		pkt, err := r.receiveLinkPacket(buf)
		if err != nil {
			return 0, err
		}
		// The link layer header was stripped in place; move the packet down so
		// the bytes start at buf[0] like a raw IP socket delivers them.
		return copy(buf, pkt), nil
	}
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if isWouldBlockUnix(err) {
				return 0, errWouldBlock
			}
			return 0, err
		}
		return n, nil
	}
}

// ReceivePacket is Receive for the relay's hot path: it returns a slice instead
// of a length so a capture source with its own link header can hand out a
// sub-slice and avoid copying every packet.
func (r *RawSock) ReceivePacket(buf []byte) ([]byte, error) {
	if r.kind == rawKindIP {
		for {
			n, _, err := unix.Recvfrom(r.fd, buf, 0)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				if isWouldBlockUnix(err) {
					return nil, errWouldBlock
				}
				return nil, err
			}
			return buf[:n], nil
		}
	}
	return r.receiveLinkPacket(buf)
}

// errWouldBlock is the platform independent "nothing queued" signal.
var errWouldBlock = errors.New("raw socket: would block")

func isWouldBlockUnix(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}

// WouldBlock reports whether err indicates a temporarily empty receive queue.
func WouldBlock(err error) bool { return errors.Is(err, errWouldBlock) }

// SetNonblocking enables or disables non-blocking mode.
func (r *RawSock) SetNonblocking(on bool) error { return unix.SetNonblock(r.fd, on) }

// WaitReadable blocks until the socket has data or the timeout elapses.
func (r *RawSock) WaitReadable(timeoutMs int) (bool, error) {
	ready, err := PollReady([]PollOne{{FD: uintptr(r.fd)}}, timeoutMs)
	if err != nil {
		return false, err
	}
	return len(ready) > 0, nil
}

// FD exposes the socket descriptor so one poll call can cover many sockets.
func (r *RawSock) FD() uintptr { return uintptr(r.fd) }

// RawCaptureLoop reads packets until stop is closed, invoking fn for each.
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
		ready, _ := r.WaitReadable(100)
		if !ready {
			continue
		}
		for i := 0; i < 64; i++ {
			pkt, err := r.ReceivePacket(buf)
			if err != nil {
				if WouldBlock(err) {
					break
				}
				return err
			}
			if len(pkt) == 0 {
				continue
			}
			if err := fn(pkt); err != nil {
				return err
			}
		}
	}
}

// PollOne describes one socket to wait on.
type PollOne struct {
	FD     uintptr
	Events int16
}

// PollReady parks until any of the sockets has data (or the timeout elapses) and
// returns the indices that are readable.
//
// A single poll covering every socket of an "all protocols" rule is what keeps
// an idle relay cheap: one call for ~250 sockets instead of one per socket.
func PollReady(socks []PollOne, timeoutMs int) ([]int, error) {
	if len(socks) == 0 {
		return nil, nil
	}
	if timeoutMs < 0 {
		timeoutMs = 0
	}
	fds := make([]unix.PollFd, len(socks))
	for i, s := range socks {
		fds[i] = unix.PollFd{Fd: int32(s.FD), Events: unix.POLLIN}
	}
	for {
		n, err := unix.Poll(fds, timeoutMs)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
		ready := make([]int, 0, n)
		for i := range fds {
			rev := fds[i].Revents
			if rev == 0 {
				continue
			}
			if rev&(unix.POLLIN|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				ready = append(ready, i)
			}
			fds[i].Revents = 0
		}
		return ready, nil
	}
}

// InterfaceIndexForIP finds the interface carrying ip.
func InterfaceIndexForIP(ip net.IP) (index int, name string, ok bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, "", false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, "", false
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var got net.IP
			switch v := a.(type) {
			case *net.IPNet:
				got = v.IP
			case *net.IPAddr:
				got = v.IP
			}
			if got != nil && got.Equal(ip4) {
				return ifc.Index, ifc.Name, true
			}
		}
	}
	return 0, "", false
}

// PrimaryInterface returns the interface a promiscuous capture should attach to
// when the rule names no address.
func PrimaryInterface() (index int, name string, err error) {
	if idx, nm, ok := platformPrimaryInterface(); ok {
		return idx, nm, nil
	}
	// Fall back to the first interface that is up, not loopback, and carries an
	// IPv4 address. That is the right answer on a machine with a single NIC and
	// a harmless guess elsewhere.
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, "", err
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			var got net.IP
			switch v := a.(type) {
			case *net.IPNet:
				got = v.IP
			case *net.IPAddr:
				got = v.IP
			}
			if got != nil && got.To4() != nil {
				return ifc.Index, ifc.Name, nil
			}
		}
	}
	return 0, "", errors.New("找不到可用的非回环 IPv4 网卡用于混杂捕获")
}

// pickSniffInterface resolves the interface a sniffing rule captures on.
func pickSniffInterface(bindIP net.IP) (index int, name string, err error) {
	if bindIP != nil && !bindIP.IsUnspecified() {
		if idx, nm, ok := InterfaceIndexForIP(bindIP); ok {
			return idx, nm, nil
		}
		return 0, "", fmt.Errorf("监听地址 %v 不属于本机任何网卡", bindIP)
	}
	return PrimaryInterface()
}

// htons converts a 16 bit value to network byte order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
