package engine

import (
	"encoding/binary"
	"net"
	"testing"

	"l4fwd/internal/config"
	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// TestProbeRawMalformedPackets feeds the raw relay packets that are too short or
// structurally odd. None may panic: the capture socket is reachable by anything
// on the segment.
func TestRawRelaySurvivesMalformedPackets(t *testing.T) {
	rl, _ := newTestRawListener(t, "200")
	defer rl.Stop()

	cases := [][]byte{
		nil,
		{0x45},           // truncated header
		make([]byte, 19), // 19 bytes, no header
		func() []byte { b := make([]byte, 20); b[0] = 0x45; return b }(), // zero total length
		func() []byte { b := make([]byte, 40); b[0] = 0x4f; return b }(), // IHL beyond buffer
		append([]byte{0x45, 0, 0, 24, 0, 1, 0, 0, 64, 200, 0, 0}, []byte("bad-addrs")...),
	}
	for i, pkt := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			rl.handlePacket(pkt)
		}()
	}

	// A payload shorter than the port header cannot be translated; the packet is
	// still forwarded unchanged rather than dropped, which keeps a bespoke
	// protocol's own error handling in charge.
	short := make([]byte, 20+2)
	short[0] = 0x45
	binary.BigEndian.PutUint16(short[2:], uint16(len(short)))
	short[8] = 64
	short[9] = 200
	copy(short[12:16], net.IPv4(172, 16, 0, 50).To4())
	copy(short[16:20], net.IPv4(172, 16, 0, 32).To4())
	binary.BigEndian.PutUint16(short[10:], netutil.Checksum(short[:20]))
	fake := &fakeSender{}
	rl.send = fake
	rl.handlePacket(short)
	if len(fake.sent) != 1 {
		t.Fatalf("packet with a short payload was dropped instead of forwarded (sent=%d)", len(fake.sent))
	}
	if got := fake.sent[0][20:]; string(got) != string(short[20:]) {
		t.Fatalf("short payload was modified: %q -> %q", short[20:], got)
	}
}

// TestProbeRawRuleWithoutTargetPort covers a raw rule that matches every packet
// of a protocol (no port filter): it must forward without a target port.
func TestRawRuleWithoutTargetPortForwards(t *testing.T) {
	rule := &config.Rule{ID: "noport", Kind: config.KindRaw, Protocol: "200",
		ListenHost: "172.16.0.32", TargetHost: "172.16.0.99", Enabled: true}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if rule.TargetPort != 0 {
		t.Fatalf("target port = %d, want 0", rule.TargetPort)
	}
	rl, err := NewRawListener(rule, config.Settings{}, stats.NewRuleStats(), quietLogger())
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	rl.sendIP = net.IPv4(172, 16, 0, 32)
	rl.listenIPs = []net.IP{net.IPv4(172, 16, 0, 32)}
	rl.target = net.IPv4(172, 16, 0, 99)
	fake := &fakeSender{}
	rl.send = fake
	defer rl.Stop()

	pkt := buildPacket(t, net.IPv4(172, 16, 0, 50), net.IPv4(172, 16, 0, 32), 200, 7, 0, 0, []byte("no-port-filter"))
	rl.handlePacket(pkt)
	if len(fake.sent) != 1 {
		t.Fatalf("packet not forwarded (sent=%d)", len(fake.sent))
	}
}
