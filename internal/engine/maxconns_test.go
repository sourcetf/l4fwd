package engine

import (
	"fmt"
	"net"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/stats"
)

// TestProbeMaxConnsEnforced checks the connection limit is actually honoured:
// beyond the limit the relay must refuse (and record) instead of accepting.
func TestTCPMaxConnsIsEnforced(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(3 * time.Second) // hold the connection open
			}(c)
		}
	}()

	port := freePort(t)
	st := stats.NewRuleStats()
	rule := &config.Rule{ID: "maxconns", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, MaxConns: 2}
	l := NewTCPListener(rule, config.Settings{DialTimeoutSec: 2}, st, quietLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer l.Stop()

	var conns []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("accepted connection %d failed: %v", i, err)
		}
		conns = append(conns, c)
	}
	time.Sleep(300 * time.Millisecond)

	// The third one must not be served: it is closed right away.
	third, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = third.Close()
	time.Sleep(300 * time.Millisecond)

	snap := st.Snapshot()
	if snap.Active > 2 {
		t.Fatalf("active connections = %d, want at most 2", snap.Active)
	}
	if snap.Errors == 0 {
		t.Fatal("refusing a connection over the limit must be recorded as an error")
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
