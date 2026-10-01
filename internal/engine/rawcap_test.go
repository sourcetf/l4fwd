package engine

import (
	"net"
	"testing"

	"l4fwd/internal/config"
	"l4fwd/internal/stats"
)

// TestRawSessionTableIsBounded checks the raw relay's session table under a flood
// of invented clients. A raw flood only has to invent source addresses or ports,
// so without a ceiling each invented client would pin a proxy port, its mappings
// and its buffers until the idle TTL expired.
func TestRawSessionTableIsBounded(t *testing.T) {
	_, listen, target := rawTestAddresses(t)

	const cap = 50
	rule := &config.Rule{ID: "rawcap", Kind: config.KindRaw, Protocol: "200",
		ListenHost: listen.String(), TargetHost: target.String(), Enabled: true,
		PayloadPorts: true, UDPSessionTTLSec: 600, MaxConns: cap}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rl, err := NewRawListener(rule, config.Settings{UDPSessionTTLSec: 600}, stats.NewRuleStats(), quietLogger())
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	rl.sendIP = listen
	rl.listenIPs = []net.IP{listen, net.IPv4zero}
	rl.target = target
	fake := &fakeSender{}
	rl.send = fake
	defer rl.Stop()

	if rl.sessionLimit != cap {
		t.Fatalf("session limit = %d, want the configured %d", rl.sessionLimit, cap)
	}

	// Ten times the cap worth of distinct clients, each with its own port.
	for i := 0; i < cap*10; i++ {
		src := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		pkt := buildPacket(t, src, listen, 200, uint16(1000+i), 0, 0,
			[]byte{0x1f, 0x90, byte(i >> 8), byte(i), 'x'})
		rl.handlePacket(pkt)
	}

	if got := rl.Sessions(); got > cap {
		t.Fatalf("session table grew to %d, above the limit of %d", got, cap)
	}
	if got := rl.denied.Load(); got == 0 {
		t.Fatal("clients refused by the limit were not counted")
	}
	// The packets that were accepted must still have gone out.
	if len(fake.sent) == 0 {
		t.Fatal("nothing was forwarded at all")
	}
	t.Logf("flood: sessions=%d refused=%d forwarded=%d", rl.Sessions(), rl.denied.Load(), len(fake.sent))
}

// TestRawSessionLimitDefaultsAndCeiling documents the default and the clamp.
func TestRawSessionLimitDefaultsAndCeiling(t *testing.T) {
	mk := func(maxConns int) *RawListener {
		rule := &config.Rule{ID: "rawcapdef", Kind: config.KindRaw, Protocol: "200",
			ListenHost: "172.16.0.32", TargetHost: "172.16.0.99", Enabled: true, MaxConns: maxConns}
		if err := rule.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		rl, err := NewRawListener(rule, config.Settings{}, stats.NewRuleStats(), quietLogger())
		if err != nil {
			t.Fatalf("listener: %v", err)
		}
		return rl
	}
	if got := mk(0).sessionLimit; got != rawSessionMemoryBudget {
		t.Fatalf("default limit = %d, want %d", got, rawSessionMemoryBudget)
	}
	if got := mk(25).sessionLimit; got != 25 {
		t.Fatalf("explicit limit = %d, want 25", got)
	}
	if got := mk(1 << 20).sessionLimit; got != rawSessionMaxCeiling {
		t.Fatalf("limit = %d, want the ceiling %d", got, rawSessionMaxCeiling)
	}
}
