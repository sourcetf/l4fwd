package engine

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/stats"
)

// TestUDPSessionCapBoundsMemory is the guard against a spoofed-source flood: a
// relay with no session cap would allocate one socket, one goroutine and one
// 64 KiB buffer per invented client address. With the cap in place the table must
// stop growing and the memory must stay bounded.
func TestUDPSessionCapBoundsMemory(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteToUDP(buf[:n], addr)
		}
	}()

	port := freePort(t)
	const cap = 40
	rule := &config.Rule{ID: "cap", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, UDPSessionTTLSec: 600, MaxConns: cap}
	u := NewUDPListener(rule, config.Settings{UDPSessionTTLSec: 600, BufferKB: 64}, stats.NewRuleStats(), quietLogger())
	if err := u.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer u.Stop()
	if u.limit != cap {
		t.Fatalf("limit = %d, want the configured %d", u.limit, cap)
	}

	// 4x the cap worth of distinct clients.
	var clients []*net.UDPConn
	for i := 0; i < cap*4; i++ {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		_, _ = c.Write([]byte(fmt.Sprintf("flood-%d", i)))
		clients = append(clients, c)
	}
	time.Sleep(1500 * time.Millisecond)

	if got := u.Sessions(); got > cap {
		t.Fatalf("session table grew to %d, above the cap of %d", got, cap)
	}
	if got := u.denied.Load(); got == 0 {
		t.Fatal("clients refused by the cap were not counted")
	}
	if got := runtime.NumGoroutine(); got > cap*3+100 {
		t.Fatalf("goroutines = %d, expected roughly one per session", got)
	}
	t.Logf("sessions=%d denied=%d goroutines=%d", u.Sessions(), u.denied.Load(), runtime.NumGoroutine())

	for _, c := range clients {
		_ = c.Close()
	}
}

// TestUDPSessionCapDefaultsAndCeiling documents the behaviour when the rule does
// not set maxConns, and that an absurd value is clamped.
func TestUDPSessionCapDefaultsAndCeiling(t *testing.T) {
	mk := func(maxConns, bufferKB int) *UDPListener {
		rule := &config.Rule{ID: "capdef", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: freePort(t),
			TargetHost: "127.0.0.1", TargetPort: 1, Enabled: true, MaxConns: maxConns}
		return NewUDPListener(rule, config.Settings{BufferKB: bufferKB}, stats.NewRuleStats(), quietLogger())
	}

	// Without maxConns the cap comes from the memory budget: a 64 KiB buffer buys
	// 64 MiB / 64 KiB = 1024 sessions.
	if got := mk(0, 64).limit; got != udpSessionMemoryBudget/(64<<10) {
		t.Fatalf("default limit = %d, want %d", got, udpSessionMemoryBudget/(64<<10))
	}
	// A bigger buffer buys proportionally fewer sessions, but never fewer than the
	// floor that keeps ordinary traffic working.
	if got := mk(0, 1024).limit; got != udpSessionMinDefault {
		t.Fatalf("limit with a 1 MiB buffer = %d, want the floor %d", got, udpSessionMinDefault)
	}
	// An explicit maxConns wins, and is clamped at the ceiling.
	if got := mk(10, 64).limit; got != 10 {
		t.Fatalf("explicit limit = %d, want 10", got)
	}
	if got := mk(1<<30, 64).limit; got != udpSessionMaxCeiling {
		t.Fatalf("limit = %d, want the ceiling %d", got, udpSessionMaxCeiling)
	}
}
