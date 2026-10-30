//go:build linux || openbsd

// Package e2e: raw socket endpoint for Linux and OpenBSD, deliberately
// independent of netutil so a bug in the relay's own socket wrapper cannot hide
// itself. Send and receive use separate sockets, the way a relay does.

package e2e

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	e2eBinName = "l4fwd"
	// Linux and OpenBSD treat the whole 127.0.0.0/8 block as local, so no alias
	// addresses have to be configured for the raw tests.
	defaultClient = "127.0.0.2"
	defaultListen = "127.0.0.1"
	defaultTarget = "127.0.0.3"
)

func e2eDefaults() (client, listen, target string) {
	return defaultClient, defaultListen, defaultTarget
}

func isElevated() bool { return os.Geteuid() == 0 }

func privilegeName() string { return "root 或 CAP_NET_RAW" }

type rawSock struct {
	recvFd int
	sendFd int
	proto  int
	ip     net.IP

	packets chan rawPacket
	stop    chan struct{}
	once    sync.Once
}

func openRaw(t *testing.T, proto int, ip net.IP) *rawSock {
	t.Helper()
	p4 := ip.To4()
	if p4 == nil {
		t.Fatalf("openRaw: %v is not IPv4", ip)
	}
	sa := &unix.SockaddrInet4{Addr: [4]byte{p4[0], p4[1], p4[2], p4[3]}}

	recvFd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, proto)
	if err != nil {
		t.Fatalf("socket(proto=%d): %v（需要 root）", proto, err)
	}
	if err := unix.Bind(recvFd, sa); err != nil {
		_ = unix.Close(recvFd)
		t.Fatalf("bind %v: %v", ip, err)
	}
	if err := unix.SetNonblock(recvFd, true); err != nil {
		_ = unix.Close(recvFd)
		t.Fatalf("set non-blocking: %v", err)
	}

	sendFd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, proto)
	if err != nil {
		_ = unix.Close(recvFd)
		t.Fatalf("socket send(proto=%d): %v", proto, err)
	}
	if err := unix.SetsockoptInt(sendFd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(recvFd)
		_ = unix.Close(sendFd)
		t.Fatalf("IP_HDRINCL: %v", err)
	}
	if err := unix.Bind(sendFd, sa); err != nil {
		_ = unix.Close(recvFd)
		_ = unix.Close(sendFd)
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

func (r *rawSock) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		n, _, err := unix.Recvfrom(r.recvFd, buf, 0)
		if err != nil {
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
		if ihl < 20 || n < ihl {
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
		_ = unix.Close(r.recvFd)
		_ = unix.Close(r.sendFd)
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

// sendRaw transmits an already assembled IPv4 packet.
func (r *rawSock) sendRaw(t *testing.T, pkt []byte, dst net.IP) {
	t.Helper()
	p4 := dst.To4()
	if p4 == nil {
		t.Fatalf("sendRaw: %v is not IPv4", dst)
	}
	sa := &unix.SockaddrInet4{Addr: [4]byte{p4[0], p4[1], p4[2], p4[3]}}
	done := make(chan error, 1)
	go func() { done <- unix.Sendto(r.sendFd, pkt, 0, sa) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sendto %v: %v", dst, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("sendto %v blocked for 5s", dst)
	}
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
