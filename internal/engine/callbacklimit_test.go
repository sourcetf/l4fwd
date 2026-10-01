package engine

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/stats"
)

// TestTransparentManyConnectionsExhaustCallbackTable pushes well past the number
// of connections a long lived forwarder sees in a day.
//
// Each gated accept used to register a fresh Go callback with the runtime
// (syscall.NewCallback inside acceptOnce). The runtime keys callbacks by their
// function value, so a new closure per connection is a new table entry, and
// entry 2000 makes the runtime throw "too many callback functions" — the process
// dies. Nothing about the traffic is unusual: it is just a lot of short
// connections, which is exactly what a forwarded SSH/shell port produces.
func TestTransparentManyConnectionsExhaustCallbackTable(t *testing.T) {
	if testing.Short() {
		t.Skip("long running")
	}
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
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "many", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	lg := logx.New(logx.Error, 50)
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 3}, stats.NewRuleStats(), lg)
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()

	// 2500 is comfortably past the runtime's 2000 callback slots.
	const rounds = 2500
	addr := fmt.Sprintf("127.0.0.1:%d", listenPort)
	for i := 0; i < rounds; i++ {
		c, err := net.DialTimeout("tcp4", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("round %d: dial: %v", i, err)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			_ = c.Close()
			t.Fatalf("round %d: write: %v", i, err)
		}
		got := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil {
			_ = c.Close()
			t.Fatalf("round %d: read: %v", i, err)
		}
		_ = c.Close()
	}
}
