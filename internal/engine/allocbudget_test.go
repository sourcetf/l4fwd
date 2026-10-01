package engine

import (
	"net"
	"testing"

	"l4fwd/internal/netutil"
)

// nullSender is a packetSender that records nothing, so allocation counts reflect
// the relay rather than the test double. (The recording fakeSender deliberately
// copies every packet it is given; the real sender hands the buffer to Winsock
// and does not keep it.)
type nullSender struct{ calls int64 }

func (s *nullSender) Send([]byte, net.IP) error { s.calls++; return nil }
func (s *nullSender) Close() error              { return nil }

// TestRawHotPathAllocationBudget pins the per-packet allocation count of the raw
// relay: zero. Each allocation is a GC obligation for every packet the tool
// forwards, and on an "all protocols" rule this is *the* hot path.
//
// The budget is asserted rather than logged because an allocation is easy to
// reintroduce accidentally — building a map key from a string, calling net.IPv4,
// copying an address or a packet buffer out of the way — and none of those show
// up as a functional failure.
func TestRawHotPathAllocationBudget(t *testing.T) {
	rl, _ := newTestRawListener(t, "200")
	rl.send = &nullSender{}
	pkt := benchPacket(512)
	rl.handlePacket(pkt) // establish the session
	h, _ := netutil.ParseHeader(pkt)
	pl := pkt[h.IHL:]
	ident, hasIdent := rl.flowOf(pl)
	sess, _ := rl.sessionFor(h, ident, hasIdent)
	// net.IPv4 allocates, so the destination is built once here instead of inside
	// the measured closure.
	dstIP := net.IPv4(10, 0, 0, 1)

	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{"ParseHeader", func() { _, _ = netutil.ParseHeader(pkt) }},
		{"clientKey", func() { _ = rl.clientKey(h, ident, hasIdent) }},
		{"replyLookupKey", func() { _, _ = rl.replyLookupKey(h, pl) }},
		{"sessionFor (hit)", func() { _, _ = rl.sessionFor(h, ident, hasIdent) }},
		{"isOwnEgress", func() { _ = rl.isOwnEgress(h, pl) }},
		{"matchesClient", func() { _ = rl.matchesClient(h, pl) }},
		{"isOurAddress", func() { _ = rl.isOurAddress(h.Dst) }},
		{"rememberSent", func() { rl.rememberSent(pkt) }},
		{"sentSeen", func() { _ = rl.sentSeen(h, pl) }},
		{"rewriteToTarget", func() { _ = rl.rewriteToTarget(pkt, h, pl, sess) }},
		{"send (real shape)", func() { _ = rl.send.Send(pkt, dstIP) }},
		{"handlePacket (whole)", func() { rl.handlePacket(pkt) }},
	} {
		got := testing.AllocsPerRun(3000, tc.fn)
		t.Logf("  %-20s %.2f allocs/op", tc.name, got)
		if got > 0 {
			t.Errorf("%s allocates %.2f times per call, budget is 0", tc.name, got)
		}
	}
}

// TestRawHotPathHandlesManySessions checks the per-packet cost does not depend on
// the size of the session table: a lookup must be a map hit, never a scan.
func TestRawHotPathHandlesManySessions(t *testing.T) {
	rl, _ := newTestRawListener(t, "200")
	rl.send = &nullSender{}
	pkt := benchPacket(512)
	rl.handlePacket(pkt)

	rl.mu.Lock()
	for i := len(rl.byClient); i < rawSessionMaxCeiling; i++ {
		s := &rawSession{
			key:      clientKey{ip: [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}, port: uint16(i)},
			clientIP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
			targetIP: net.IPv4(172, 16, 0, 99),
			viaIP:    net.IPv4(172, 16, 0, 32),
		}
		rl.byClient[s.key] = s
	}
	size := len(rl.byClient)
	rl.mu.Unlock()

	if allocs := testing.AllocsPerRun(2000, func() { rl.handlePacket(pkt) }); allocs > 0 {
		t.Fatalf("with %d sessions a packet costs %.2f allocs (budget 0)", size, allocs)
	}
	t.Logf("会话表 %d 条时每包分配 0 次", size)
}
