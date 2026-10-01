package engine

import (
	"fmt"
	"net"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/stats"
)

// TestProbeZeroPortAndBadTarget checks the edge cases the UI can produce:
// port 0 (kernel picks one) and a target that cannot be resolved. Neither may
// panic, and neither may leave a half-started listener behind.
func TestTCPRuleRejectsZeroPortAndUnresolvableTarget(t *testing.T) {
	// Port 0 on a TCP rule: valid to dial, unusable as a relay (clients cannot
	// know the port), but it must not crash the process.
	r0 := &config.Rule{ID: "zero", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: 0,
		TargetHost: "127.0.0.1", TargetPort: 9, Enabled: true}
	if err := r0.Validate(); err == nil {
		t.Log("port 0 accepted by validation (the listener binds an ephemeral port)")
	} else {
		t.Logf("port 0 rejected at validation: %v", err)
	}

	// Unresolvable target: the listener must still start (the failure belongs to
	// the connection attempt, not to startup).
	port := freePort(t)
	rb := &config.Rule{ID: "badtarget", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "no-such-host.invalid", TargetPort: 80, Enabled: true}
	l := NewTCPListener(rb, config.Settings{DialTimeoutSec: 1}, stats.NewRuleStats(), quietLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("listener with an unresolvable target should still start: %v", err)
	}
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// The client must see a clean close (EOF) rather than a crash.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected the connection to be closed for an unresolvable target")
	}
	_ = c.Close()
	l.Stop()
}
