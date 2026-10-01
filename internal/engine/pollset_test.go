//go:build windows

package engine

import (
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestRawPollSetWakesOnPacket checks the shared poller reports a socket that has
// data. A missed wakeup here means silently dropped packets rather than an error,
// so it is checked against a real raw socket.
func TestRawPollSetWakesOnPacket(t *testing.T) {
	_, listen, _ := rawTestAddresses(t)
	sock := openPollTestSocket(t, listen)
	defer sock.close()

	set := newRawPollSet()
	defer set.stop()

	wake, remove := set.register(sock.recvFD())
	defer remove()
	if set.count() != 1 {
		t.Fatalf("set holds %d sockets, want 1", set.count())
	}

	// Nothing pending: no wakeup within two poll intervals.
	select {
	case <-wake:
		t.Fatal("poller reported data on an idle socket")
	case <-time.After(2 * time.Duration(pollSetInterval)):
	}

	sock.sendOne(t)
	select {
	case <-wake:
	case <-time.After(3 * time.Second):
		t.Fatal("poller did not wake up for a socket that received a packet")
	}
}

// TestRawPollSetStopsPromptly checks the poller goroutine exits on shutdown
// without relying on a socket close to interrupt it (Windows does not interrupt a
// parked WSAPoll when the socket is closed — verified while writing this).
func TestRawPollSetStopsPromptly(t *testing.T) {
	set := newRawPollSet()
	wake, _ := set.register(0x4321)
	done := make(chan struct{})
	go func() { set.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poll set did not stop within 5s")
	}
	select {
	case <-wake:
		t.Fatal("a socket registered with a stopped set produced a wakeup")
	default:
	}
}

// TestRawPollSetRemovesSockets checks register/remove bookkeeping, so a stopped
// listener does not stay in the set.
func TestRawPollSetRemovesSockets(t *testing.T) {
	set := newRawPollSet()
	defer set.stop()

	var removes []func()
	for i := 0; i < 8; i++ {
		_, remove := set.register(uintptr(0x1000 + i))
		removes = append(removes, remove)
		if set.count() != i+1 {
			t.Fatalf("after %d registrations the set holds %d", i+1, set.count())
		}
	}
	for i, remove := range removes {
		remove()
		if set.count() != len(removes)-i-1 {
			t.Fatalf("after %d removals the set holds %d", i+1, set.count())
		}
	}
}

// pollTestSocket is a raw socket bound to a test address, used to exercise the
// poller against real Winsock behaviour.
type pollTestSocket struct {
	fd   windows.Handle
	send windows.Handle
	ip   net.IP
}

func openPollTestSocket(t *testing.T, ip net.IP) *pollTestSocket {
	t.Helper()
	ip4 := ip.To4()
	sa := &windows.SockaddrInet4{Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}}

	recvFd, err := windows.WSASocket(int32(windows.AF_INET), int32(windows.SOCK_RAW), 200, nil, 0, 0)
	if err != nil {
		t.Fatalf("WSASocket recv: %v", err)
	}
	if err := windows.Bind(recvFd, sa); err != nil {
		windows.Closesocket(recvFd)
		t.Fatalf("bind %v: %v", ip, err)
	}
	one := uint32(1)
	var ret uint32
	if err := windows.WSAIoctl(recvFd, 0x8004667E, (*byte)(unsafe.Pointer(&one)), 4, nil, 0, &ret, nil, 0); err != nil {
		windows.Closesocket(recvFd)
		t.Fatalf("FIONBIO: %v", err)
	}

	sendFd, err := windows.WSASocket(int32(windows.AF_INET), int32(windows.SOCK_RAW), 200, nil, 0, 0)
	if err != nil {
		windows.Closesocket(recvFd)
		t.Fatalf("WSASocket send: %v", err)
	}
	if err := windows.SetsockoptInt(sendFd, windows.IPPROTO_IP, windows.IP_HDRINCL, 1); err != nil {
		windows.Closesocket(recvFd)
		windows.Closesocket(sendFd)
		t.Fatalf("IP_HDRINCL: %v", err)
	}
	if err := windows.Bind(sendFd, sa); err != nil {
		windows.Closesocket(recvFd)
		windows.Closesocket(sendFd)
		t.Fatalf("bind send %v: %v", ip, err)
	}
	return &pollTestSocket{fd: recvFd, send: sendFd, ip: ip}
}

func (s *pollTestSocket) close() {
	if s.fd != 0 {
		windows.Closesocket(s.fd)
	}
	if s.send != 0 {
		windows.Closesocket(s.send)
	}
}

func (s *pollTestSocket) recvFD() uintptr { return uintptr(s.fd) }

// sendOne puts one proto-200 datagram on the wire addressed to this socket.
func (s *pollTestSocket) sendOne(t *testing.T) {
	t.Helper()
	payload := []byte("poll-wakeup-test")
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[2], pkt[3] = byte(total>>8), byte(total)
	pkt[4], pkt[5] = 0x12, 0x34
	pkt[6], pkt[7] = 0x40, 0x00 // DF
	pkt[8] = 64
	pkt[9] = 200
	copy(pkt[12:16], s.ip.To4())
	copy(pkt[16:20], s.ip.To4())
	sum := ipHeaderSum(pkt[:20])
	pkt[10], pkt[11] = byte(sum>>8), byte(sum)
	copy(pkt[20:], payload)

	ip4 := s.ip.To4()
	var rsa [16]byte
	*(*int16)(unsafe.Pointer(&rsa[0])) = int16(windows.AF_INET)
	copy(rsa[4:8], ip4)
	var sent uint32
	wb := &windows.WSABuf{Len: uint32(len(pkt)), Buf: &pkt[0]}
	if err := windows.WSASendTo(s.send, wb, 1, &sent, 0, (*windows.RawSockaddrAny)(unsafe.Pointer(&rsa[0])), int32(len(rsa)), nil, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// ipHeaderSum computes the one's complement IPv4 header checksum.
func ipHeaderSum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
