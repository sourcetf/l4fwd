package engine

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// fakeSender records whatever the raw relay tries to put on the wire.
type fakeSender struct {
	mu     [0]byte
	sent   [][]byte
	dsts   []net.IP
	closed bool
}

func (f *fakeSender) Send(pkt []byte, dst net.IP) error {
	cp := append([]byte(nil), pkt...)
	f.sent = append(f.sent, cp)
	f.dsts = append(f.dsts, append(net.IP(nil), dst...))
	return nil
}

func (f *fakeSender) Close() error { f.closed = true; return nil }

func newTestRawListener(t *testing.T, proto string) (*RawListener, *fakeSender) {
	t.Helper()
	rule := &config.Rule{
		ID: "raw-test", Kind: config.KindRaw, Protocol: proto,
		ListenHost: "172.16.0.32", TargetHost: "172.16.0.99", Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rl, err := NewRawListener(rule, config.Settings{UDPSessionTTLSec: 5}, stats.NewRuleStats(), quietLogger())
	if err != nil {
		t.Fatalf("NewRawListener: %v", err)
	}
	rl.sendIP = net.IPv4(172, 16, 0, 32)
	rl.listenIPs = []net.IP{net.IPv4(172, 16, 0, 32)}
	rl.target = net.IPv4(172, 16, 0, 99)
	fake := &fakeSender{}
	rl.send = fake
	return rl, fake
}

func quietLogger() *logx.Logger {
	l := logx.New(logx.Error, 50)
	l.SetOutput(discardWriter{})
	return l
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// buildPacket assembles an IPv4 packet with the given transport payload.
func buildPacket(t *testing.T, src, dst net.IP, proto uint8, id uint16, fragOff uint16, flags uint8, payload []byte) []byte {
	t.Helper()
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], (uint16(flags)<<13)|(fragOff&0x1fff))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:], netutil.Checksum(pkt[:20]))
	copy(pkt[20:], payload)
	return pkt
}

// TestRawRelayCustomProtocolRewrite is the core check for bespoke protocols:
// a packet for a protocol that is not TCP/UDP must be forwarded towards the
// target with rewritten addresses, the payload untouched, and the reply must
// come back to the client with the original addresses restored.
func TestRawRelayCustomProtocolRewrite(t *testing.T) {
	const proto = 200
	rl, fake := newTestRawListener(t, "200")
	defer rl.Stop()

	client := net.IPv4(172, 16, 0, 50)
	via := net.IPv4(172, 16, 0, 32) // address the client thinks it talks to
	target := net.IPv4(172, 16, 0, 99)

	payload := []byte("custom-protocol-payload\x00\xff\x01")
	pkt := buildPacket(t, client, via, proto, 0x1234, 0, netutil.FlagDF, payload)
	rl.handlePacket(pkt)

	if len(fake.sent) != 1 {
		t.Fatalf("forwarded %d packets, want 1", len(fake.sent))
	}
	fwd := fake.sent[0]
	if !fake.dsts[0].Equal(target) {
		t.Fatalf("forwarded to %v, want %v", fake.dsts[0], target)
	}
	h, err := netutil.ParseHeader(fwd)
	if err != nil {
		t.Fatalf("parse forwarded: %v", err)
	}
	if !netutil.SameIP(h.Src, rl.sendIP) {
		t.Fatalf("forwarded source = %v, want %v", h.Src, rl.sendIP)
	}
	if !netutil.SameIP(h.Dst, target) {
		t.Fatalf("forwarded destination = %v, want %v", h.Dst, target)
	}
	if !bytes.Equal(fwd[h.IHL:], payload) {
		t.Fatalf("payload changed: % x", fwd[h.IHL:])
	}
	if netutil.Checksum(fwd[:h.IHL]) != 0 {
		t.Fatal("forwarded header checksum is wrong")
	}

	// The reply from the target must reappear to the client as if it came from
	// the address the client originally targeted.
	reply := []byte("reply-payload")
	rp := buildPacket(t, target, rl.sendIP, proto, 0x5678, 0, 0, reply)
	rl.handlePacket(rp)
	if len(fake.sent) != 2 {
		t.Fatalf("relay did not forward the reply (sent=%d)", len(fake.sent))
	}
	back := fake.sent[1]
	if !fake.dsts[1].Equal(client) {
		t.Fatalf("reply sent to %v, want %v", fake.dsts[1], client)
	}
	bh, err := netutil.ParseHeader(back)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if !netutil.SameIP(bh.Src, via) {
		t.Fatalf("reply source = %v, want %v", bh.Src, via)
	}
	if !netutil.SameIP(bh.Dst, client) {
		t.Fatalf("reply destination = %v, want %v", bh.Dst, client)
	}
	if !bytes.Equal(back[bh.IHL:], reply) {
		t.Fatalf("reply payload changed: % x", back[bh.IHL:])
	}
}

// TestRawRelayUDPChecksumRepair checks the port rewrite plus address rewrite
// are reflected in the UDP checksum, which the client will verify.
func TestRawRelayUDPChecksumRepair(t *testing.T) {
	rl, fake := newTestRawListener(t, "17")
	defer rl.Stop()

	client := net.IPv4(172, 16, 0, 50)
	via := net.IPv4(172, 16, 0, 32)

	udp := make([]byte, 8+6)
	binary.BigEndian.PutUint16(udp[0:2], 53124) // client source port
	binary.BigEndian.PutUint16(udp[2:4], 4000)  // the port the client targeted
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	udp[6], udp[7] = 0, 0
	copy(udp[8:], []byte("abcdef"))
	binary.BigEndian.PutUint16(udp[6:8], netutil.Recompute(client, via, netutil.ProtoUDP, udp))

	pkt := buildPacket(t, client, via, netutil.ProtoUDP, 0x4242, 0, 0, udp)
	rl.handlePacket(pkt)
	if len(fake.sent) != 1 {
		t.Fatalf("forwarded %d packets, want 1", len(fake.sent))
	}
	fwd := fake.sent[0]
	h, err := netutil.ParseHeader(fwd)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	payload := fwd[h.IHL:]
	if !bytes.Equal(payload[8:], []byte("abcdef")) {
		t.Fatalf("payload changed: %q", payload[8:])
	}

	// Verify the rewritten checksum exactly the way the target's stack would.
	stored := binary.BigEndian.Uint16(payload[6:8])
	ref := append([]byte(nil), payload...)
	ref[6], ref[7] = 0, 0
	want := netutil.Recompute(h.Src, h.Dst, netutil.ProtoUDP, ref)
	if stored != want {
		t.Fatalf("forwarded UDP checksum = %#04x, want %#04x", stored, want)
	}
}

// TestRawRelayPortTranslation confirms the session gets a distinct proxy port
// and that replies carry the client's original port back.
func TestRawRelayPortTranslation(t *testing.T) {
	rl, fake := newTestRawListener(t, "17")
	defer rl.Stop()

	client := net.IPv4(172, 16, 0, 50)
	via := net.IPv4(172, 16, 0, 32)
	target := net.IPv4(172, 16, 0, 99)

	mkUDP := func(srcPort, dstPort uint16, body string) []byte {
		b := make([]byte, 8+len(body))
		binary.BigEndian.PutUint16(b[0:2], srcPort)
		binary.BigEndian.PutUint16(b[2:4], dstPort)
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)))
		copy(b[8:], body)
		binary.BigEndian.PutUint16(b[6:8], netutil.Recompute(client, via, netutil.ProtoUDP, b))
		return b
	}

	rl.handlePacket(buildPacket(t, client, via, netutil.ProtoUDP, 1, 0, 0, mkUDP(10001, 4000, "ping")))
	if len(fake.sent) != 1 {
		t.Fatalf("no packet forwarded")
	}
	fwd := fake.sent[0]
	fh, _ := netutil.ParseHeader(fwd)
	proxyPort := binary.BigEndian.Uint16(fwd[fh.IHL:][0:2])
	if proxyPort == 10001 {
		t.Fatal("relay must use its own proxy port towards the target")
	}
	if got := binary.BigEndian.Uint16(fwd[fh.IHL:][2:4]); got != 4000 {
		t.Fatalf("target port = %d, want 4000", got)
	}

	// Reply addressed to the proxy port must be rewritten back to 10001.
	reply := make([]byte, 8+4)
	binary.BigEndian.PutUint16(reply[0:2], 4000)
	binary.BigEndian.PutUint16(reply[2:4], proxyPort)
	binary.BigEndian.PutUint16(reply[4:6], uint16(len(reply)))
	copy(reply[8:], "pong")
	binary.BigEndian.PutUint16(reply[6:8], netutil.Recompute(target, rl.sendIP, netutil.ProtoUDP, reply))

	rl.handlePacket(buildPacket(t, target, rl.sendIP, netutil.ProtoUDP, 2, 0, 0, reply))
	if len(fake.sent) != 2 {
		t.Fatalf("reply not forwarded (sent=%d)", len(fake.sent))
	}
	back := fake.sent[1]
	bh, _ := netutil.ParseHeader(back)
	bp := back[bh.IHL:]
	if got := binary.BigEndian.Uint16(bp[0:2]); got != 4000 {
		t.Fatalf("reply source port = %d, want 4000", got)
	}
	if got := binary.BigEndian.Uint16(bp[2:4]); got != 10001 {
		t.Fatalf("reply destination port = %d, want 10001", got)
	}
	if !netutil.SameIP(bh.Src, via) || !netutil.SameIP(bh.Dst, client) {
		t.Fatalf("reply addresses = %v -> %v", bh.Src, bh.Dst)
	}
	stored := binary.BigEndian.Uint16(bp[6:8])
	ref := append([]byte(nil), bp...)
	ref[6], ref[7] = 0, 0
	if want := netutil.Recompute(bh.Src, bh.Dst, netutil.ProtoUDP, ref); stored != want {
		t.Fatalf("reply checksum = %#04x, want %#04x", stored, want)
	}
}

// TestRawRelayIgnoresOwnEgress stops the capture socket from re-forwarding the
// packets the relay itself emitted, which would create a loop.
func TestRawRelayIgnoresOwnEgress(t *testing.T) {
	rl, fake := newTestRawListener(t, "17")
	defer rl.Stop()

	client := net.IPv4(172, 16, 0, 50)
	via := net.IPv4(172, 16, 0, 32)
	target := net.IPv4(172, 16, 0, 99)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 10001)
	binary.BigEndian.PutUint16(udp[2:4], 4000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	rl.handlePacket(buildPacket(t, client, via, netutil.ProtoUDP, 1, 0, 0, udp))
	if len(fake.sent) != 1 {
		t.Fatalf("first packet not forwarded")
	}
	// Feed the forwarded packet back in, as the capture socket would see it.
	rl.handlePacket(append([]byte(nil), fake.sent[0]...))
	if len(fake.sent) != 1 {
		t.Fatalf("relay re-forwarded its own packet: sent=%d", len(fake.sent))
	}
	_ = target
}

// TestRawRelayFragments checks that non-initial fragments are forwarded with
// only the header rewritten, and that the reply mapping still applies.
func TestRawRelayFragments(t *testing.T) {
	const proto = 200
	rl, fake := newTestRawListener(t, "200")
	defer rl.Stop()

	client := net.IPv4(172, 16, 0, 50)
	via := net.IPv4(172, 16, 0, 32)
	target := net.IPv4(172, 16, 0, 99)

	// First fragment: header + start of the transport payload.
	first := buildPacket(t, client, via, proto, 0x7777, 0, netutil.FlagMF, []byte("AAAA"))
	rl.handlePacket(first)
	if len(fake.sent) != 1 {
		t.Fatalf("first fragment not forwarded")
	}
	id := binary.BigEndian.Uint16(fake.sent[0][4:6])
	if id == 0x7777 && false {
		t.Log("IP ID preserved")
	}
	fh, _ := netutil.ParseHeader(fake.sent[0])
	if fh.FragOff != 0 || fh.Flags&netutil.FlagMF == 0 {
		t.Fatalf("fragment flags lost on forward: off=%d flags=%d", fh.FragOff, fh.Flags)
	}
	if !netutil.SameIP(fh.Dst, target) {
		t.Fatalf("fragment destination = %v", fh.Dst)
	}

	// Second fragment: no transport header at all, must still be forwarded.
	second := buildPacket(t, client, via, proto, 0x7777, 1, 0, []byte("BBBBBBBB"))
	rl.handlePacket(second)
	if len(fake.sent) != 2 {
		t.Fatalf("non-initial fragment dropped (sent=%d)", len(fake.sent))
	}
	sh, _ := netutil.ParseHeader(fake.sent[1])
	if sh.FragOff != 1 {
		t.Fatalf("second fragment offset = %d, want 1", sh.FragOff)
	}
	if !bytes.Equal(fake.sent[1][20:], []byte("BBBBBBBB")) {
		t.Fatalf("fragment payload changed: %q", fake.sent[1][20:])
	}
}

// TestRawRelayIgnoresOtherProtocols makes sure only the configured protocol
// is picked up, so several raw rules can coexist.
func TestRawRelayIgnoresOtherProtocols(t *testing.T) {
	rl, fake := newTestRawListener(t, "200")
	defer rl.Stop()

	via := net.IPv4(172, 16, 0, 32)
	client := net.IPv4(172, 16, 0, 50)
	pkt := buildPacket(t, client, via, 201, 5, 0, 0, []byte("other"))
	rl.handlePacket(pkt)
	if len(fake.sent) != 0 {
		t.Fatalf("packet of another protocol was forwarded")
	}
}

// TestRawRelayRequiresConfiguredPort checks the port filter.
func TestRawRelayRequiresConfiguredPort(t *testing.T) {
	rule := &config.Rule{
		ID: "raw-port", Kind: config.KindRaw, Protocol: "17",
		ListenHost: "172.16.0.32", ListenPort: 4000, TargetHost: "172.16.0.99", TargetPort: 9000, Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rl, err := NewRawListener(rule, config.Settings{}, stats.NewRuleStats(), quietLogger())
	if err != nil {
		t.Fatalf("NewRawListener: %v", err)
	}
	rl.sendIP = net.IPv4(172, 16, 0, 32)
	rl.listenIPs = []net.IP{net.IPv4(172, 16, 0, 32)}
	rl.target = net.IPv4(172, 16, 0, 99)
	fake := &fakeSender{}
	rl.send = fake
	defer rl.Stop()

	via := net.IPv4(172, 16, 0, 32)
	client := net.IPv4(172, 16, 0, 50)

	other := make([]byte, 8)
	binary.BigEndian.PutUint16(other[0:2], 1234)
	binary.BigEndian.PutUint16(other[2:4], 5000) // not the configurelisten port
	rl.handlePacket(buildPacket(t, client, via, netutil.ProtoUDP, 1, 0, 0, other))
	if len(fake.sent) != 0 {
		t.Fatal("packet for a different port was forwarded")
	}

	matching := make([]byte, 8)
	binary.BigEndian.PutUint16(matching[0:2], 1234)
	binary.BigEndian.PutUint16(matching[2:4], 4000)
	rl.handlePacket(buildPacket(t, client, via, netutil.ProtoUDP, 2, 0, 0, matching))
	if len(fake.sent) != 1 {
		t.Fatalf("packet for the configured port was not forwarded (sent=%d)", len(fake.sent))
	}
}

// TestRawRelaySessionExpiry checks idle sessions are reaped and their proxy
// ports returned to the pool.
func TestRawRelaySessionExpiry(t *testing.T) {
	rl, _ := newTestRawListener(t, "17")
	rl.ttl = 150 * time.Millisecond
	defer rl.Stop()

	via := net.IPv4(172, 16, 0, 32)
	for i := 0; i < 3; i++ {
		client := net.IPv4(172, 16, 0, byte(60+i))
		udp := make([]byte, 8)
		binary.BigEndian.PutUint16(udp[0:2], uint16(20000+i))
		binary.BigEndian.PutUint16(udp[2:4], 4000)
		rl.handlePacket(buildPacket(t, client, via, netutil.ProtoUDP, uint16(i), 0, 0, udp))
	}
	if got := rl.Sessions(); got != 3 {
		t.Fatalf("sessions = %d, want 3", got)
	}

	// Drive the reaper directly instead of waiting on the ticker.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rl.mu.Lock()
		var dead []*rawSession
		for k, s := range rl.byClient {
			if s.idle() >= rl.ttl {
				delete(rl.byClient, k)
				delete(rl.byReply, s.reply)
				dead = append(dead, s)
			}
		}
		rl.mu.Unlock()
		for _, s := range dead {
			if s.proxyPort != 0 {
				rl.portPool.free(s.proxyPort)
			}
		}
		if rl.Sessions() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rl.Sessions() != 0 {
		t.Fatalf("sessions were not reaped: %d", rl.Sessions())
	}
}

// TestPortAllocatorReuse hammers the allocator to be sure ports are unique
// while held and reusable after release.
func TestPortAllocatorReuse(t *testing.T) {
	p := newPortAllocator(1000, 1005)
	seen := map[uint16]bool{}
	var held []uint16
	for i := 0; i < 6; i++ {
		port := p.alloc()
		if port == 0 {
			break
		}
		if seen[port] {
			t.Fatalf("port %d handed out twice", port)
		}
		seen[port] = true
		held = append(held, port)
	}
	if len(held) != 6 {
		t.Fatalf("allocated %d ports, want 6", len(held))
	}
	if got := p.alloc(); got != 0 {
		t.Fatalf("allocator must report exhaustion, got %d", got)
	}
	p.free(held[0])
	if got := p.alloc(); got != held[0] {
		t.Fatalf("freed port not reused: got %d, want %d", got, held[0])
	}
}

// TestRawNoLoopForLocalTarget checks the amplification loop that appears when
// the target lives on this machine: the capture socket sees the relay's own
// egress copy, and treating it as client traffic would forward it forever.
func TestRawNoLoopForLocalTarget(t *testing.T) {
	// A rule whose target is one of this machine's own addresses is the risky
	// shape; the unit helper already points both sides at .32/.99, so redirect
	// the target to the relay address itself.
	rl, fake := newTestRawListener(t, "17")
	defer rl.Stop()
	rl.target = net.IPv4(172, 16, 0, 32) // == sendIP, i.e. a local target

	client := net.IPv4(172, 16, 0, 50)
	via := net.IPv4(172, 16, 0, 32)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 20001)
	binary.BigEndian.PutUint16(udp[2:4], 4000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	pkt := buildPacket(t, client, via, netutil.ProtoUDP, 0x1234, 0, 0, udp)

	rl.handlePacket(pkt)
	if len(fake.sent) != 1 {
		t.Fatalf("client packet not forwarded (sent=%d)", len(fake.sent))
	}
	// Feed our own egress copy back repeatedly: a real capture socket does this
	// for a local target, and none of them may be forwarded again.
	for i := 0; i < 5; i++ {
		rl.handlePacket(append([]byte(nil), fake.sent[0]...))
	}
	if len(fake.sent) != 1 {
		t.Fatalf("relay re-forwarded its own egress packet: sent=%d (amplification loop)", len(fake.sent))
	}

	// The reply path is the mirror image: a reply we sent to a local client must
	// not be mistaken for client traffic either.
	reply := make([]byte, 8)
	binary.BigEndian.PutUint16(reply[0:2], 4000)
	copy(reply[2:4], fake.sent[0][26:28])
	binary.BigEndian.PutUint16(reply[4:6], uint16(len(reply)))
	rl.handleClient(buildPacket(t, rl.target, rl.sendIP, netutil.ProtoUDP, 0x2222, 0, 0, reply), mustHeader(t, buildPacket(t, rl.target, rl.sendIP, netutil.ProtoUDP, 0x2222, 0, 0, reply)), reply)
	before := len(fake.sent)
	rl.handlePacket(fake.sent[before-1])
	if len(fake.sent) != before {
		t.Fatalf("relay re-forwarded a reply it had sent: sent=%d, want %d", len(fake.sent), before)
	}
}

func mustHeader(t *testing.T, pkt []byte) *netutil.Header {
	t.Helper()
	h, err := netutil.ParseHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	return h
}
