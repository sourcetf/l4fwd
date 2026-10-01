package config

import (
	"encoding/json"
	"math/rand"
	"testing"
)

// TestProbeConfigFuzzRoundTrip verifies random configurations survive a JSON
// round trip and still validate, which the dashboard relies on: it marshals a
// config, ships it over HTTP, and the agent re-validates it.
func TestConfigSurvivesJSONRoundTripFuzz(t *testing.T) {
	rng := rand.New(rand.NewSource(4242))
	kinds := []string{KindTCP, KindUDP, KindRaw}
	hosts := []string{"", "0.0.0.0", "127.0.0.1", "172.16.0.32"}
	targets := []string{"127.0.0.1", "10.0.0.1", "example.com"}

	for i := 0; i < 500; i++ {
		cfg := Default()
		n := rng.Intn(4)
		for j := 0; j < n; j++ {
			k := kinds[rng.Intn(len(kinds))]
			r := &Rule{
				ID:         NewID(),
				Kind:       k,
				ListenHost: hosts[rng.Intn(len(hosts))],
				ListenPort: 1024 + rng.Intn(60000),
				TargetHost: targets[rng.Intn(len(targets))],
				TargetPort: 1 + rng.Intn(65534),
				Enabled:    rng.Intn(2) == 0,
			}
			if k == KindRaw {
				r.Protocol = []string{"47", "gre", "200", "icmp", "tcp", "all"}[rng.Intn(6)]
				if r.Protocol == "all" {
					r.ListenPort = 1024 + rng.Intn(60000)
				}
				if rng.Intn(3) == 0 {
					r.PayloadPorts = true
				}
				if rng.Intn(3) == 0 {
					r.Sniff = true
				}
			}
			if err := r.Validate(); err != nil {
				continue // a random invalid rule is fine; skip it
			}
			// Skip duplicates the store would reject so the round trip stays legal.
			dup := false
			for _, ex := range cfg.Rules {
				if _, clash := sharedKey(ex, r); clash {
					dup = true
					break
				}
			}
			if !dup {
				cfg.Rules = append(cfg.Rules, r)
			}
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back Config
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, r := range back.Rules {
			if err := r.Validate(); err != nil {
				t.Fatalf("rule %s did not survive the round trip: %v\n%s", r.ID, err, data)
			}
		}
	}
}
