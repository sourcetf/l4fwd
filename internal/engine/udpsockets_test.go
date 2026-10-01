package engine

import (
	"net"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/stats"
)

// countHandles returns the number of handles owned by this process, via
// GetProcessHandleCount. A rule that leaks sockets would show up here.
func countHandles() int {
	return osHandleCount()
}

// TestUDPPortsDoNotLeakSockets churns UDP sessions through a rule and checks the
// process handle count does not grow without bound: every client session owns an
// upstream socket that must be released when the session is reaped.
func TestUDPPortsDoNotLeakSockets(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteToUDP(buf[:n], addr)
		}
	}()

	port := freePort(t)
	rule := &config.Rule{ID: "fds", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, UDPSessionTTLSec: 1}
	u := NewUDPListener(rule, config.Settings{UDPSessionTTLSec: 1, BufferKB: 64}, stats.NewRuleStats(), quietLogger())
	if err := u.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer u.Stop()

	before := countHandles()
	for round := 0; round < 8; round++ {
		for i := 0; i < 12; i++ {
			c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				t.Fatalf("round %d client %d: %v", round, i, err)
			}
			_, _ = c.Write([]byte("ping"))
			buf := make([]byte, 64)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Read(buf)
			_ = c.Close()
		}
		// Let the session TTL reap the upstream sockets.
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) && u.Sessions() > 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	time.Sleep(500 * time.Millisecond)
	after := countHandles()
	if after > before+40 {
		t.Fatalf("handle count grew from %d to %d over 8 rounds of 12 sessions", before, after)
	}
	t.Logf("handles before=%d after=%d sessions=%d", before, after, u.Sessions())
}
