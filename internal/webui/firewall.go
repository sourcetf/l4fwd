package webui

import (
	"fmt"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/platform"
)

// ensureFirewallRule performs the actual netsh call behind the dashboard's
// 「放行防火墙」button. It is a variable so tests can exercise the endpoint
// without writing rules into the host's firewall.
var ensureFirewallRule = platform.EnsureFirewallRule

// firewallRulesFor lists the inbound allow rules the config needs. It mirrors the
// CLI's -firewall so both act on exactly the same set of ports.
//
// A "raw" rule for a single IP protocol owns no port (the Windows firewall cannot
// filter by protocol number), while a TCP-shaped or "all protocol" raw rule does
// terminate TCP and is therefore covered.
func firewallRulesFor(cfg *config.Config) []platform.FirewallRule {
	seen := map[string]bool{}
	var out []platform.FirewallRule
	add := func(name string, port int, proto string) {
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, platform.FirewallRule{Name: name, Port: port, Proto: proto, Profile: "any"})
	}
	for _, r := range cfg.Rules {
		if r.ListenPort == 0 {
			continue
		}
		switch {
		case r.Kind == config.KindRaw && r.IsProtocolAll():
			add(fmt.Sprintf("l4fwd ALL TCP %d", r.ListenPort), r.ListenPort, "TCP")
			add(fmt.Sprintf("l4fwd ALL UDP %d", r.ListenPort), r.ListenPort, "UDP")
		case r.Kind == config.KindRaw && r.Transport() == config.RawTransparent:
			add(fmt.Sprintf("l4fwd RAW-TCP %d", r.ListenPort), r.ListenPort, "TCP")
		case r.Kind == config.KindTCP:
			add(fmt.Sprintf("l4fwd TCP %d", r.ListenPort), r.ListenPort, "TCP")
		case r.Kind == config.KindUDP:
			add(fmt.Sprintf("l4fwd UDP %d", r.ListenPort), r.ListenPort, "UDP")
		}
	}
	return out
}

// firewallStatus reports which of the rule ports are not yet allowed inbound, so
// the dashboard can warn about the most common cause of "nothing is forwarded".
// Off Windows the platform reports Supported=false and the dashboard hides the
// whole feature instead of pretending the ports are closed.
func firewallStatus(cfg *config.Config, log *logx.Logger) platform.FirewallStatus {
	if !platform.FirewallSupported() {
		return platform.InspectFirewall(nil)
	}
	rules := firewallRulesFor(cfg)
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name)
	}
	st := platform.InspectFirewall(names)
	if st.Error != "" {
		log.Debugf("web", "无法检查防火墙状态：%s", st.Error)
	}
	return st
}
