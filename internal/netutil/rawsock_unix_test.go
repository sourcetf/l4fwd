//go:build linux || openbsd

package netutil

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// rawTestPacket assembles an IPv4 packet for protocol 200 with a small payload.
func rawTestPacket(t *testing.T, src, dst net.IP, payload string) []byte {
	t.Helper()
	body := append([]byte("l4fwd-raw-test:"), payload...)
	pkt := make([]byte, 20+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], 4242)
	pkt[8] = 64
	pkt[9] = 200
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:], Checksum(pkt[:20]))
	copy(pkt[20:], body)
	return pkt
}

// TestRawSockSendsAndReceives checks the raw IP socket path both systems use for
// arbitrary protocols: IP_HDRINCL on send, a copy of matching packets on receive,
// and non-blocking polling between them.
func TestRawSockSendsAndReceives(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw sockets need root or CAP_NET_RAW")
	}
	local := net.ParseIP("127.0.0.1")
	capSock, err := OpenRawSock(RawSockOptions{Proto: 200, BindIP: local, HeaderIncl: true, RcvBufBytes: 1 << 20})
	if err != nil {
		t.Fatalf("capture socket: %v", err)
	}
	defer capSock.Close()
	snd, err := OpenRawSock(RawSockOptions{Proto: 200, BindIP: local, HeaderIncl: true, SendOnly: true})
	if err != nil {
		t.Fatalf("send socket: %v", err)
	}
	defer snd.Close()

	if got := capSock.Proto(); got != 200 {
		t.Fatalf("proto = %d", got)
	}
	pkt := rawTestPacket(t, local, local, "hello")
	if err := snd.Send(pkt, local); err != nil {
		t.Fatalf("send: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 65535)
	for {
		if time.Now().After(deadline) {
			t.Fatal("no captured copy of our own packet")
		}
		ready, err := capSock.WaitReadable(200)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if !ready {
			continue
		}
		got, err := capSock.ReceivePacket(buf)
		if err != nil {
			if WouldBlock(err) {
				continue
			}
			t.Fatalf("receive: %v", err)
		}
		if len(got) < 20 || got[9] != 200 {
			continue
		}
		if string(got[20:]) == "l4fwd-raw-test:hello" {
			return
		}
	}
}

// TestSniffCapturesLoopback checks the promiscuous capture path can be opened and
// sees a packet for its protocol. Linux uses AF_PACKET, OpenBSD /dev/bpf; both
// need privilege.
func TestSniffCapturesLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("promiscuous capture needs root")
	}
	local := net.ParseIP("127.0.0.1")
	sniff, err := OpenRawSock(RawSockOptions{Proto: 200, BindIP: local, Sniff: true, RcvBufBytes: 1 << 20})
	if err != nil {
		t.Skipf("promiscuous capture unavailable here: %v", err)
	}
	defer sniff.Close()
	if !sniff.Sniffing() {
		t.Fatal("socket does not report sniffing")
	}
	t.Logf("capture interface: %s", sniff.Interface())

	snd, err := OpenRawSock(RawSockOptions{Proto: 200, BindIP: local, HeaderIncl: true, SendOnly: true})
	if err != nil {
		t.Fatalf("send socket: %v", err)
	}
	defer snd.Close()
	if err := snd.Send(rawTestPacket(t, local, local, "sniff"), local); err != nil {
		t.Fatalf("send: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		ready, err := sniff.WaitReadable(200)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if !ready {
			continue
		}
		got, err := sniff.ReceivePacket(buf)
		if err != nil {
			if WouldBlock(err) {
				continue
			}
			t.Fatalf("receive: %v", err)
		}
		if len(got) >= 20+len("l4fwd-raw-test:sniff") && got[0]>>4 == 4 &&
			string(got[20:20+len("l4fwd-raw-test:sniff")]) == "l4fwd-raw-test:sniff" {
			return
		}
	}
	t.Fatal("capture socket did not see the packet sent on loopback")
}
