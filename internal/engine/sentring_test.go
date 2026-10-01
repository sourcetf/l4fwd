package engine

import (
	"net"
	"testing"
	"time"

	"l4fwd/internal/netutil"
)

// TestSentRingRecognisesRecentEgress is the regression guard for the echo
// backstop: it has to match a packet the relay transmitted moments ago, and it
// has to stop matching once that packet is old enough that a repeat is a
// different packet reusing the same identifiers.
func TestSentRingRecognisesRecentEgress(t *testing.T) {
	ring := newSentRing(sentRingSize)
	key := sentKey{proto: 200, id: 0x1234, src: [4]byte{172, 16, 0, 32}, dst: [4]byte{172, 16, 0, 99}}
	if ring.seen(key) {
		t.Fatal("an empty ring matched something")
	}
	ring.remember(key)
	if !ring.seen(key) {
		t.Fatal("a transmitted packet was not recognised")
	}
	// A different port pair is a different packet.
	other := key
	other.srcP = 41000
	if ring.seen(other) {
		t.Fatal("a packet with different ports matched")
	}

	// Age the entry out and check it stops matching.
	ring.mu.Lock()
	for i := range ring.at {
		ring.at[i] = time.Now().Add(-sentRingWindow - time.Second).UnixNano()
	}
	ring.mu.Unlock()
	if ring.seen(key) {
		t.Fatal("an expired transmission still matched")
	}
}

// TestSentRingIsBounded checks the ring does not grow without bound and keeps the
// newest keys, which are the ones that matter for echo detection.
func TestSentRingIsBounded(t *testing.T) {
	ring := newSentRing(sentRingSize)
	last := sentRingSize*4 - 1
	for i := 0; i <= last; i++ {
		ring.remember(sentKey{proto: 200, id: uint16(i), src: [4]byte{10, 0, byte(i >> 8), byte(i)}})
	}
	// The last transmitted packet must still be found...
	newest := sentKey{proto: 200, id: uint16(last), src: [4]byte{10, 0, byte(last >> 8), byte(last)}}
	if !ring.seen(newest) {
		t.Fatal("the most recent transmission was not remembered")
	}
	// ...and the ring must not have kept everything.
	ring.mu.Lock()
	stored := len(ring.keys)
	ring.mu.Unlock()
	if stored != sentRingSize {
		t.Fatalf("ring holds %d entries, want %d", stored, sentRingSize)
	}
}

// TestEgressRingCatchesAnUnmatchedEcho drives a packet through the listener whose
// source matches our send address but which the two cheap shapes in isOwnEgress do
// not cover, so the ring is the only thing that can stop it being forwarded again.
func TestEgressRingCatchesAnUnmatchedEcho(t *testing.T) {
	rl, fake := newTestRawListener(t, "17")
	defer rl.Stop()
	rl.rule.ListenPort = 0 // no port gate, so the packet reaches the egress check

	client := net.IPv4(172, 16, 0, 50)
	via := net.IPv4(172, 16, 0, 32)
	udp := []byte{0x27, 0x11, 0x0f, 0xa1, 0x00, 0x08, 0, 0} // ports 10001 -> 4001
	rl.handlePacket(buildPacket(t, client, via, netutil.ProtoUDP, 0x4321, 0, 0, udp))
	if len(fake.sent) != 1 {
		t.Fatalf("first packet not forwarded (sent=%d)", len(fake.sent))
	}
	sent := fake.sent[0]

	// Feed the egress copy back in with its destination rewritten to an address
	// that is neither the target nor a known proxy, so only the ring can match it.
	echo := append([]byte(nil), sent...)
	copy(echo[16:20], net.IPv4(172, 16, 0, 200).To4())
	rl.handlePacket(echo)
	if len(fake.sent) != 1 {
		t.Fatalf("the ring did not suppress an unmatched echo: sent=%d", len(fake.sent))
	}

	// A packet we never sent is still forwarded, so the ring is not a blanket ban.
	// It is addressed to a local address with a different IP ID and a source port that
	// is not one of the proxy ports (the pool is 40000-60000), so none of the other
	// suppression rules apply to it.
	other := append([]byte(nil), sent...)
	copy(other[16:20], net.IPv4(172, 16, 0, 32).To4()) // a local address, so the address check passes
	other[4], other[5] = 0x99, 0x99                    // different IP ID
	other[20], other[21] = 0x2e, 0xe0
	rl.handlePacket(other)
	if len(fake.sent) != 2 {
		t.Fatalf("an unrelated packet was dropped: sent=%d", len(fake.sent))
	}
}
