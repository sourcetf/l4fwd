package engine

import (
	"testing"

	"l4fwd/internal/config"
	"l4fwd/internal/stats"
)

// TestAllProtocolRuleSplitsSessionBudget checks the "all protocol" rule keeps its
// session budget under control: 252 parts must not each hold a full one.
//
// The TCP part is the deliberate exception. A raw or UDP session can be created
// from a spoofed packet, so their caps bound what an attacker can pin; a TCP
// connection only exists because a client completed a handshake, and the even
// share (10 connections in this configuration) is far below what a single
// forwarded port serves — measured, a 30-connection burst had half of its
// connections accepted and then dropped.
func TestAllProtocolRuleSplitsSessionBudget(t *testing.T) {
	rule := &config.Rule{ID: "budget", Kind: config.KindRaw, Protocol: "all",
		ListenHost: "172.16.0.32", ListenPort: 9000, TargetHost: "172.16.0.99", TargetPort: 9000,
		Enabled: true, MaxConns: 2520}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	ml, err := NewMultiListener(rule, config.Settings{}, stats.NewRuleStats(), quietLogger())
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	total := 0
	tcpConns := 0
	for i, part := range ml.parts {
		switch p := part.(type) {
		case *RawListener:
			total += p.sessionLimit
			if p.sessionLimit != 10 {
				t.Errorf("part %s limit = %d, want 10", ml.names[i], p.sessionLimit)
			}
		case *UDPListener:
			total += p.limit
		case *TransparentTCPListener:
			tcpConns = p.rule.MaxConns
			total += tcpConns
		}
	}
	// The raw and UDP parts stay inside the rule's budget...
	if rest := total - tcpConns; rest > 2520 {
		t.Fatalf("non-TCP capacity %d exceeds the rule budget 2520", rest)
	}
	// ...and the TCP half keeps enough connections for a real port. This rule sets
	// maxConns itself, so its value is honoured; what matters is that the even
	// share (10 here) is not what the TCP listener was given.
	if tcpConns < transparentMinConns {
		t.Fatalf("TCP half allows %d connections, want at least the floor %d (the even share would be 10)",
			tcpConns, transparentMinConns)
	}
	t.Logf("parts=%d raw/udp capacity=%d tcp=%d (budget 2520)", len(ml.parts), total-tcpConns, tcpConns)
}
