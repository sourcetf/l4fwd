package cli

import (
	"testing"

	"l4fwd/internal/config"
)

// TestBuildCommandLineRuleAllProtocols checks the -proto all shorthand produces
// a rule that carries TCP, UDP and every other IP protocol.
func TestBuildCommandLineRuleAllProtocols(t *testing.T) {
	rule, err := buildCommandLineRule(Options{
		Kind:       "raw",
		Protocol:   "all",
		ListenSpec: "19002",
		TargetSpec: "10.0.0.9:19002",
	})
	if err != nil {
		t.Fatalf("build rule: %v", err)
	}
	if !rule.IsProtocolAll() {
		t.Fatalf("protocol = %q, want all", rule.Protocol)
	}
	if rule.ListenPort != 19002 || rule.TargetPort != 19002 {
		t.Fatalf("ports = %d/%d", rule.ListenPort, rule.TargetPort)
	}
	if rule.RawTransport != config.RawTransparent {
		t.Fatalf("transport = %q, want transparent after validation", rule.RawTransport)
	}
}

// TestBuildCommandLineRuleRejectsBadProtocol keeps a typo from silently
// creating a rule that never matches.
func TestBuildCommandLineRuleRejectsBadProtocol(t *testing.T) {
	if _, err := buildCommandLineRule(Options{Kind: "raw", Protocol: "notaproto", TargetSpec: "10.0.0.9"}); err == nil {
		t.Fatal("unknown protocol must be rejected")
	}
	if _, err := buildCommandLineRule(Options{Kind: "raw", TargetSpec: "10.0.0.9"}); err == nil {
		t.Fatal("a raw rule without -proto must be rejected")
	}
}

// TestFirewallRuleNamesCoverEveryPortingShape is the regression test for the
// reported "ssh -p22 ... 压根没有转发啊，22你都没开" case: the rule was a raw
// "all protocols" one, and the old firewall helper skipped every raw rule, so
// port 22 was never opened and inbound connections timed out (loopback worked,
// which hid the problem).
func TestFirewallRuleNamesCoverEveryPortingShape(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []*config.Rule{
		{ID: "ssh", Kind: config.KindTCP, ListenHost: "0.0.0.0", ListenPort: 22, TargetHost: "10.0.0.1", TargetPort: 22},
		{ID: "all", Kind: config.KindRaw, Protocol: "all", RawTransport: config.RawTransparent,
			ListenHost: "0.0.0.0", ListenPort: 2200, TargetHost: "10.0.0.1", TargetPort: 22},
		{ID: "trans", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
			ListenHost: "0.0.0.0", ListenPort: 2222, TargetHost: "10.0.0.1", TargetPort: 22},
		{ID: "dns", Kind: config.KindUDP, ListenHost: "0.0.0.0", ListenPort: 5353, TargetHost: "10.0.0.53", TargetPort: 53},
		{ID: "gre", Kind: config.KindRaw, Protocol: "gre", ListenHost: "0.0.0.0", TargetHost: "10.0.0.2"},
	}
	for _, r := range cfg.Rules {
		if err := r.Validate(); err != nil {
			t.Fatalf("rule %s: %v", r.ID, err)
		}
	}

	names := FirewallRuleNames(cfg)
	want := []string{
		"l4fwd TCP 22",
		"l4fwd ALL TCP 2200",
		"l4fwd ALL UDP 2200",
		"l4fwd RAW-TCP 2222",
		"l4fwd UDP 5353",
	}
	if len(names) != len(want) {
		t.Fatalf("firewall rules = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("firewall rules = %v, want %v", names, want)
		}
	}

	// A single-protocol raw rule owns no port and must not produce a rule.
	for _, n := range names {
		if n == "l4fwd ALL TCP 0" || n == "l4fwd GRE" {
			t.Fatalf("unexpected rule for a portless / protocol-typed rule: %v", names)
		}
	}
}
