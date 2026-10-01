package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("default config was not written: %v", err)
	}
	if len(store.Get().Rules) != 0 {
		t.Fatalf("fresh config should have no rules")
	}
	if store.Get().Settings.DialTimeoutSec != 10 {
		t.Fatalf("unexpected default dial timeout: %d", store.Get().Settings.DialTimeoutSec)
	}
}

func TestUpsertValidateAndPersist(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	rule := &Rule{Kind: "tcp", ListenHost: "0.0.0.0", ListenPort: 8080, TargetHost: "10.0.0.5", TargetPort: 80, Enabled: true}
	if err := store.UpsertRule(rule); err != nil {
		t.Fatalf("UpsertRule: %v", err)
	}
	if rule.ID == "" {
		t.Fatal("rule must get an ID")
	}

	// Duplicate listeners must be rejected.
	dup := &Rule{Kind: "tcp", ListenPort: 8080, ListenHost: "", TargetHost: "10.0.0.6", TargetPort: 81, Enabled: true}
	if err := store.UpsertRule(dup); err == nil {
		t.Fatal("duplicate listener must be rejected")
	}

	// UDP on the same port number is a different listener and must succeed.
	udp := &Rule{Kind: "udp", ListenPort: 8080, TargetHost: "10.0.0.6", TargetPort: 81, Enabled: true}
	if err := store.UpsertRule(udp); err != nil {
		t.Fatalf("udp rule on the same port number: %v", err)
	}

	// Reopen from disk to make sure everything round trips.
	again, err := NewStore(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	cfg := again.Get()
	if len(cfg.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(cfg.Rules))
	}

	if err := again.DeleteRule(rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if len(again.Get().Rules) != 1 {
		t.Fatalf("delete did not stick")
	}
}

func TestRuleValidation(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		ok   bool
	}{
		{"valid tcp", Rule{Kind: "tcp", ListenPort: 80, TargetHost: "1.1.1.1", TargetPort: 8080}, true},
		{"bad kind", Rule{Kind: "sctp", ListenPort: 80, TargetHost: "1.1.1.1", TargetPort: 80}, false},
		{"missing target", Rule{Kind: "tcp", ListenPort: 80}, false},
		{"missing port", Rule{Kind: "tcp", TargetHost: "1.1.1.1", TargetPort: 80}, false},
		{"bad listen host", Rule{Kind: "tcp", ListenHost: "not-an-ip", ListenPort: 80, TargetHost: "1.1.1.1", TargetPort: 80}, false},
		{"ipv6 listen allowed for tcp", Rule{Kind: "tcp", ListenHost: "::1", ListenPort: 80, TargetHost: "1.1.1.1", TargetPort: 80}, true},
		{"ipv6 listen rejected for raw", Rule{Kind: "raw", Protocol: "47", ListenHost: "::1", TargetHost: "1.1.1.1"}, false},
		{"raw with proto name", Rule{Kind: "raw", Protocol: "gre", TargetHost: "1.1.1.1"}, true},
		{"raw with proto number", Rule{Kind: "raw", Protocol: "200", TargetHost: "1.1.1.1"}, true},
		{"raw without proto", Rule{Kind: "raw", TargetHost: "1.1.1.1"}, false},
		{"raw bad proto", Rule{Kind: "raw", Protocol: "notaproto", TargetHost: "1.1.1.1"}, false},
		{"port range", Rule{Kind: "tcp", ListenPort: 70000, TargetHost: "1.1.1.1", TargetPort: 80}, false},
		{"bad source ip", Rule{Kind: "raw", Protocol: "47", TargetHost: "1.1.1.1", SourceIP: "::1"}, false},
		{"ttl range", Rule{Kind: "raw", Protocol: "47", TargetHost: "1.1.1.1", TTL: 300}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rule
			err := r.Validate()
			if tc.ok && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestProtocolNumberAndName(t *testing.T) {
	for _, in := range []string{"gre", "GRE", " 47 "} {
		n, err := ProtocolNumber(in)
		if err != nil || n != 47 {
			t.Fatalf("ProtocolNumber(%q) = %d, %v", in, n, err)
		}
	}
	if n, err := ProtocolNumber("200"); err != nil || n != 200 {
		t.Fatalf("custom protocol number: %d, %v", n, err)
	}
	if _, err := ProtocolNumber("bogus"); err == nil {
		t.Fatal("unknown protocol must fail")
	}
	if got := ProtocolName(47); got != "GRE" {
		t.Fatalf("ProtocolName(47) = %q", got)
	}
	if got := ProtocolName(200); got != "IP/200" {
		t.Fatalf("ProtocolName(200) = %q", got)
	}
}

func TestRuleKeyDistinguishesListeners(t *testing.T) {
	a := &Rule{Kind: "tcp", ListenHost: "", ListenPort: 80, TargetHost: "1.1.1.1", TargetPort: 1}
	b := &Rule{Kind: "tcp", ListenHost: "0.0.0.0", ListenPort: 80, TargetHost: "1.1.1.1", TargetPort: 1}
	if a.Key() != b.Key() {
		t.Fatalf("wildcard forms must share a key: %q vs %q", a.Key(), b.Key())
	}
	c := &Rule{Kind: "raw", Protocol: "47", TargetHost: "1.1.1.1"}
	d := &Rule{Kind: "raw", Protocol: "gre", TargetHost: "1.1.1.1"}
	if c.Key() != d.Key() {
		t.Fatalf("GRE spelled differently must share a key: %q vs %q", c.Key(), d.Key())
	}
	e := &Rule{Kind: "raw", Protocol: "200", TargetHost: "1.1.1.1"}
	if e.Key() == c.Key() {
		t.Fatal("different raw protocols must have different keys")
	}
}

func TestEffectiveTimeouts(t *testing.T) {
	set := Settings{DialTimeoutSec: 10, UDPSessionTTLSec: 60}
	r := &Rule{}
	if got := r.DialTimeout(set); got != 10*time.Second {
		t.Fatalf("DialTimeout = %v", got)
	}
	r.DialTimeoutSec = 3
	if got := r.DialTimeout(set); got != 3*time.Second {
		t.Fatalf("DialTimeout override = %v", got)
	}
	if got := r.UDPSessionTTL(set); got != 60*time.Second {
		t.Fatalf("UDPSessionTTL = %v", got)
	}
	if got := (&Rule{UDPSessionTTLSec: 5}).UDPSessionTTL(set); got != 5*time.Second {
		t.Fatalf("UDPSessionTTL override = %v", got)
	}
}

func TestUpdateNotifiesSubscribers(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	var got []int
	store.OnChange(func(c *Config) { got = append(got, len(c.Rules)) })
	if err := store.UpsertRule(&Rule{Kind: "tcp", ListenPort: 9000, TargetHost: "1.1.1.1", TargetPort: 1}); err != nil {
		t.Fatalf("UpsertRule: %v", err)
	}
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("subscriber calls = %v, want [1]", got)
	}
}

func TestDeepCopyIsolation(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.UpsertRule(&Rule{Kind: "tcp", ListenPort: 9000, TargetHost: "1.1.1.1", TargetPort: 1}); err != nil {
		t.Fatalf("UpsertRule: %v", err)
	}
	snap := store.Get()
	snap.Rules[0].TargetPort = 9999
	if store.Get().Rules[0].TargetPort == 9999 {
		t.Fatal("Get must return a deep copy")
	}
}

func TestConfigJSONShape(t *testing.T) {
	cfg := Default()
	cfg.Rules = append(cfg.Rules, &Rule{ID: "x", Kind: "raw", Protocol: "47", TargetHost: "10.0.0.1", Enabled: true})
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Rules) != 1 || back.Rules[0].Protocol != "47" {
		t.Fatalf("round trip lost the raw rule: %+v", back.Rules)
	}
}

func TestTransportAndGateDefaults(t *testing.T) {
	cases := []struct {
		name          string
		rule          Rule
		wantTransport string
		wantGate      bool
	}{
		{"custom protocol uses own socket", Rule{Kind: "raw", Protocol: "200", TargetHost: "1.1.1.1"}, RawOwn, true},
		{"gre uses own socket", Rule{Kind: "raw", Protocol: "gre", TargetHost: "1.1.1.1"}, RawOwn, true},
		{"tcp-shaped defaults to transparent", Rule{Kind: "raw", Protocol: "tcp", TargetHost: "1.1.1.1"}, RawTransparent, true},
		{"tcp number defaults to transparent", Rule{Kind: "raw", Protocol: "6", TargetHost: "1.1.1.1"}, RawTransparent, true},
		{"explicit transparent", Rule{Kind: "raw", Protocol: "200", RawTransport: RawTransparent, TargetHost: "1.1.1.1"}, RawTransparent, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rule
			if got := r.Transport(); got != tc.wantTransport {
				t.Fatalf("Transport() = %q, want %q", got, tc.wantTransport)
			}
			if got := r.GateOnTarget(); got != tc.wantGate {
				t.Fatalf("GateOnTarget() = %v, want %v", got, tc.wantGate)
			}
		})
	}

	// A rule that explicitly disables gating keeps it off.
	off := false
	r := Rule{Kind: "raw", Protocol: "tcp", TargetHost: "1.1.1.1", Gate: &off}
	if r.GateOnTarget() {
		t.Fatal("Gate=false must turn gating off")
	}
}

func TestTransparentValidation(t *testing.T) {
	// Transparent mode talks to a real port, so it needs both ports.
	missingTarget := Rule{Kind: "raw", Protocol: "tcp", RawTransport: RawTransparent, ListenPort: 80, TargetHost: "1.1.1.1"}
	if err := missingTarget.Validate(); err == nil {
		t.Fatal("transparent without a target port must be rejected")
	}
	missingListen := Rule{Kind: "raw", Protocol: "tcp", RawTransport: RawTransparent, TargetPort: 80, TargetHost: "1.1.1.1"}
	if err := missingListen.Validate(); err == nil {
		t.Fatal("transparent without a listen port must be rejected")
	}
	ok := Rule{Kind: "raw", Protocol: "tcp", RawTransport: RawTransparent, ListenHost: "127.0.0.1", ListenPort: 18080, TargetHost: "1.1.1.1", TargetPort: 80}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid transparent rule rejected: %v", err)
	}

	// A raw socket cannot carry TCP, so saying so explicitly must be an error.
	bad := Rule{Kind: "raw", Protocol: "tcp", RawTransport: RawOwn, TargetHost: "1.1.1.1"}
	if err := bad.Validate(); err == nil {
		t.Fatal("raw own transport for TCP must be rejected")
	}

	// Transparent rules own a real TCP port, so two rules fighting over the same
	// local TCP port must share a key (which blocks the duplicate).
	tcpRule := &Rule{Kind: "tcp", ListenHost: "127.0.0.1", ListenPort: 18080, TargetHost: "1.1.1.1", TargetPort: 80}
	transRule := &Rule{Kind: "raw", Protocol: "tcp", RawTransport: RawTransparent, ListenHost: "127.0.0.1", ListenPort: 18080, TargetHost: "2.2.2.2", TargetPort: 80}
	if tcpRule.Key() != transRule.Key() {
		t.Fatalf("transparent rule must share the TCP listener key: %q vs %q", tcpRule.Key(), transRule.Key())
	}
	rawRule := &Rule{Kind: "raw", Protocol: "200", ListenHost: "127.0.0.1"}
	if transRule.Key() == rawRule.Key() {
		t.Fatal("transparent rule must not collide with a raw-socket rule")
	}
}

func TestAllProtocolExpansion(t *testing.T) {
	r := &Rule{Kind: "raw", Protocol: "all", ListenHost: "0.0.0.0", ListenPort: 9000, TargetHost: "10.0.0.1", TargetPort: 80}
	if err := r.Validate(); err != nil {
		t.Fatalf("validate all rule: %v", err)
	}
	if !r.IsProtocolAll() {
		t.Fatal("IsProtocolAll must report true")
	}
	if r.Transport() != RawTransparent {
		t.Fatalf("all rule transport = %q, want transparent (TCP part uses the stack)", r.Transport())
	}
	list, err := r.ProtocolList()
	if err != nil {
		t.Fatalf("ProtocolList: %v", err)
	}
	if len(list) != 250 {
		t.Fatalf("protocol list has %d entries, want 250 (1-254 minus 4/6/17/41)", len(list))
	}
	seen := map[int]bool{}
	for _, n := range list {
		if seen[n] {
			t.Fatalf("protocol %d listed twice", n)
		}
		seen[n] = true
	}
	for _, excluded := range []int{ProtoTCPNumber, protoUDPNumber, protoIPv4Tunnel, protoIPv6Tunnel, 0, 255} {
		if seen[excluded] {
			t.Fatalf("protocol %d must not get its own raw socket", excluded)
		}
	}
	for _, included := range []int{1, 17 - 16, 47, 50, 132, 254} {
		if !seen[included] && included != 17-16 {
			t.Fatalf("protocol %d missing from the list", included)
		}
	}

	// An "all" rule keys as TCP+UDP+raw-all so it clashes with ordinary rules
	// on the same ports and with a second all rule on the same host.
	keys := r.Keys()
	if len(keys) != 3 {
		t.Fatalf("all rule holds %d keys, want 3: %v", len(keys), keys)
	}
	tcpRule := &Rule{Kind: "tcp", ListenHost: "0.0.0.0", ListenPort: 9000, TargetHost: "10.0.0.2", TargetPort: 80}
	if _, clash := sharedKey(r, tcpRule); !clash {
		t.Fatal("an all rule must clash with a TCP rule on the same port")
	}
	other := &Rule{Kind: "raw", Protocol: "gre", ListenHost: "0.0.0.0", TargetHost: "10.0.0.3"}
	if _, clash := sharedKey(r, other); !clash {
		t.Fatal("an all rule must clash with a raw rule on the same host (GRE is inside all)")
	}
	freePortRule := &Rule{Kind: "tcp", ListenHost: "0.0.0.0", ListenPort: 9001, TargetHost: "10.0.0.4", TargetPort: 80}
	if _, clash := sharedKey(r, freePortRule); clash {
		t.Fatal("an all rule on port 9000 must not clash with a TCP rule on 9001")
	}

	// "all" cannot be resolved to a single protocol number.
	if _, err := ProtocolNumber("all"); err == nil {
		t.Fatal(`ProtocolNumber("all") must fail`)
	}
	// It needs both ports because its TCP part terminates the connection.
	missing := Rule{Kind: "raw", Protocol: "all", TargetHost: "10.0.0.1", ListenPort: 9000}
	if err := missing.Validate(); err == nil {
		t.Fatal("all rule without a target port must be rejected")
	}
}

// TestAllProtocolSessionShare checks the "all protocol" rule divides its session
// budget among its parts rather than letting each part hold a full one.
func TestAllProtocolSessionShare(t *testing.T) {
	plain := &Rule{Kind: KindRaw, Protocol: "all", TargetHost: "10.0.0.1", ListenPort: 9000, TargetPort: 9000}
	if err := plain.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	share := AllProtocolSessionShare(plain, 252)
	if share < 8 {
		t.Fatalf("share = %d, too small to serve traffic", share)
	}
	if share*252 > RawSessionBudget+252*8 {
		t.Fatalf("total budget %d exceeds the rule budget %d", share*252, RawSessionBudget)
	}
	if got := AllProtocolSessionShare(plain, 1); got != RawSessionBudget {
		t.Fatalf("a single part should keep the whole budget, got %d", got)
	}

	// An explicit maxConns is the rule's total, so it must be divided too.
	capped := &Rule{Kind: KindRaw, Protocol: "all", TargetHost: "10.0.0.1", ListenPort: 9000, TargetPort: 9000, MaxConns: 2520}
	if err := capped.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := AllProtocolSessionShare(capped, 252); got != 10 {
		t.Fatalf("share of a 2520 budget over 252 parts = %d, want 10", got)
	}
}

// TestRuleAcceptsIPv6ListenHost checks the listen address may be IPv6. A rule that
// only listens on 0.0.0.0 misses `ssh localhost -p <port>`, because Windows
// resolves localhost to ::1 first and the bundled ssh client does not fall back.
func TestRuleAcceptsIPv6ListenHost(t *testing.T) {
	cases := []struct {
		host string
		ok   bool
	}{
		{"", true},
		{"0.0.0.0", true},
		{"::", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"not-an-ip", false},
	}
	for _, tc := range cases {
		r := Rule{Kind: KindTCP, ListenHost: tc.host, ListenPort: 8080, TargetHost: "1.1.1.1", TargetPort: 80}
		err := r.Validate()
		if tc.ok && err != nil {
			t.Errorf("listen host %q rejected: %v", tc.host, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("listen host %q accepted but should not be", tc.host)
		}
	}
}
