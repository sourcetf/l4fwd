//go:build windows

// Package e2e: Windows raw socket endpoint used by the cross-platform end-to-end
// tests. It is deliberately independent of netutil so a bug in the relay's own
// socket wrapper cannot hide itself.

package e2e

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---------- helpers ----------

type sa4 struct {
	Family int16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// rawSock is a minimal SOCK_RAW endpoint with its own bound address.
//
// Receiving and sending use separate sockets, the same way the relay does:
// sharing one raw socket between a blocking WSARecvFrom loop and WSASendTo can
// deadlock inside the network driver.
type rawSock struct {
	recvFd windows.Handle
	sendFd windows.Handle
	proto  int
	ip     net.IP

	packets chan rawPacket
	stop    chan struct{}
	once    sync.Once
}

func openRaw(t *testing.T, proto int, ip net.IP) *rawSock {
	t.Helper()
	p4 := ip.To4()
	sa := &windows.SockaddrInet4{Addr: [4]byte{p4[0], p4[1], p4[2], p4[3]}}

	recvFd, err := windows.WSASocket(int32(windows.AF_INET), int32(windows.SOCK_RAW), int32(proto), nil, 0, 0)
	if err != nil {
		t.Fatalf("WSASocket(proto=%d): %v", proto, err)
	}
	if err := windows.Bind(recvFd, sa); err != nil {
		windows.Closesocket(recvFd)
		t.Fatalf("bind %v: %v", ip, err)
	}
	// Windows blocks inside Closesocket while a WSARecvFrom is parked on the
	// same socket, so the receive side runs non-blocking and polls.
	if err := setNonblocking(recvFd, true); err != nil {
		windows.Closesocket(recvFd)
		t.Fatalf("FIONBIO: %v", err)
	}

	sendFd, err := windows.WSASocket(int32(windows.AF_INET), int32(windows.SOCK_RAW), int32(proto), nil, 0, 0)
	if err != nil {
		windows.Closesocket(recvFd)
		t.Fatalf("WSASocket send(proto=%d): %v", proto, err)
	}
	if err := windows.SetsockoptInt(sendFd, windows.IPPROTO_IP, windows.IP_HDRINCL, 1); err != nil {
		windows.Closesocket(recvFd)
		windows.Closesocket(sendFd)
		t.Fatalf("IP_HDRINCL: %v", err)
	}
	if err := windows.Bind(sendFd, sa); err != nil {
		windows.Closesocket(recvFd)
		windows.Closesocket(sendFd)
		t.Fatalf("send bind %v: %v", ip, err)
	}

	r := &rawSock{
		recvFd:  recvFd,
		sendFd:  sendFd,
		proto:   proto,
		ip:      ip,
		packets: make(chan rawPacket, 512),
		stop:    make(chan struct{}),
	}
	go r.readLoop()
	return r
}

// setNonblocking toggles FIONBIO on a socket handle.
func setNonblocking(fd windows.Handle, on bool) error {
	var mode uint32
	if on {
		mode = 1
	}
	var ret uint32
	return windows.WSAIoctl(fd, 0x8004667E, (*byte)(unsafe.Pointer(&mode)), 4, nil, 0, &ret, nil, 0)
}

// readLoop drains the receive socket into the packets channel until Close.
func (r *rawSock) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		var n, flags uint32
		var from windows.RawSockaddrAny
		fl := int32(unsafe.Sizeof(from))
		wb := &windows.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}
		if err := windows.WSARecvFrom(r.recvFd, wb, 1, &n, &flags, &from, &fl, nil, nil); err != nil {
			select {
			case <-r.stop:
				return
			default:
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || int(n) < ihl {
			continue
		}
		p := rawPacket{
			src:      net.IPv4(buf[12], buf[13], buf[14], buf[15]),
			dst:      net.IPv4(buf[16], buf[17], buf[18], buf[19]),
			proto:    buf[9],
			body:     append([]byte(nil), buf[ihl:n]...),
			id:       binary.BigEndian.Uint16(buf[4:6]),
			fragOff:  binary.BigEndian.Uint16(buf[6:8]) & 0x1fff,
			flags:    uint8(binary.BigEndian.Uint16(buf[6:8]) >> 13),
			received: time.Now(),
		}
		if len(p.body) >= 4 {
			p.sport = binary.BigEndian.Uint16(p.body[0:2])
			p.dport = binary.BigEndian.Uint16(p.body[2:4])
			p.hasPorts = true
		}
		select {
		case r.packets <- p:
		default: // no reader: drop rather than stall the reader goroutine
		}
	}
}

func (r *rawSock) Close() {
	r.once.Do(func() {
		close(r.stop)
		_ = windows.Closesocket(r.recvFd)
		_ = windows.Closesocket(r.sendFd)
	})
}

// send writes a raw IPv4 packet built around the 4 byte port header plus body.
func (r *rawSock) send(t *testing.T, src, dst net.IP, sport, dport uint16, payload []byte, id uint16) {
	t.Helper()
	r.sendFrag(t, src, dst, sport, dport, payload, id, 0, 0)
}

// sendFrag assembles and transmits a packet with explicit fragment fields.
func (r *rawSock) sendFrag(t *testing.T, src, dst net.IP, sport, dport uint16, payload []byte, id, fragOff, flags uint16) {
	t.Helper()
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(body[0:2], sport)
	binary.BigEndian.PutUint16(body[2:4], dport)
	copy(body[4:], payload)

	pkt := make([]byte, 20+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], (flags<<13)|(fragOff&0x1fff))
	pkt[8] = 64
	pkt[9] = byte(r.proto)
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:20]))
	copy(pkt[20:], body)

	r.sendRaw(t, pkt, dst)
}

// sendRaw transmits an already assembled IPv4 packet, failing the test if the
// driver does not accept it within a few seconds.
func (r *rawSock) sendRaw(t *testing.T, pkt []byte, dst net.IP) {
	t.Helper()
	var rsa windows.RawSockaddrAny
	p := (*sa4)(unsafe.Pointer(&rsa))
	p.Family = windows.AF_INET
	copy(p.Addr[:], dst.To4())
	wb := &windows.WSABuf{Len: uint32(len(pkt)), Buf: &pkt[0]}
	done := make(chan error, 1)
	go func() {
		var sent uint32
		done <- windows.WSASendTo(r.sendFd, wb, 1, &sent, 0, &rsa, int32(unsafe.Sizeof(rsa)), nil, nil)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WSASendTo %v: %v", dst, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("WSASendTo %v blocked for 5s", dst)
	}
}

// ---------- platform defaults ----------

const e2eBinName = "l4fwd.exe"

// e2eDefaults are the addresses scripts/e2e-aliases.ps1 adds to the primary NIC.
// Windows does not hand loopback traffic to SIO_RCVALL, so the raw tests cannot
// use 127.0.0.x there.
func e2eDefaults() (client, listen, target string) {
	return "172.16.0.40", "172.16.0.32", "172.16.0.41"
}

// isElevated reports whether the process has administrator rights, which raw
// socket setup requires.
func isElevated() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	ok, err := windows.Token(0).IsMember(sid)
	return err == nil && ok
}

func privilegeName() string { return "管理员权限" }
