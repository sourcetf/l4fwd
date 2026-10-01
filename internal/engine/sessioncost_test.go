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

// sessionSet is what a flood of "clients" costs: each one is a distinct source
// address, which is exactly what a spoofed-source flood looks like.
type sessionSet struct {
	conns []*net.UDPConn
}

// TestUDPSessionMemoryCost measures the memory a set of UDP sessions costs, so the
// session cap can be chosen from evidence rather than a guess.
func TestUDPSessionMemoryCost(t *testing.T) {
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
	// A long TTL so sessions accumulate instead of being reaped mid-test.
	rule := &config.Rule{ID: "cost", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, UDPSessionTTLSec: 600}
	u := NewUDPListener(rule, config.Settings{UDPSessionTTLSec: 600, BufferKB: 64}, stats.NewRuleStats(), quietLogger())
	if err := u.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer u.Stop()

	measure := func() (uint64, int) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc, u.Sessions()
	}

	baseHeap, _ := measure()
	t.Logf("buffer per session: %d KiB", u.bufSize/1024)

	// Create 300 distinct clients, each sending one datagram.
	var clients []*net.UDPConn
	for i := 0; i < 300; i++ {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		_, _ = c.Write([]byte(fmt.Sprintf("hello-%d", i)))
		clients = append(clients, c)
	}
	time.Sleep(1500 * time.Millisecond) // let every session be created
	heap, sessions := measure()
	for _, c := range clients {
		_ = c.Close()
	}

	perSession := int64(0)
	if sessions > 0 {
		perSession = int64(heap-baseHeap) / int64(sessions)
	}
	t.Logf("sessions=%d heap=%d KiB (+%d KiB), ~%d bytes per session, goroutines=%d",
		sessions, heap/1024, (int64(heap)-int64(baseHeap))/1024, perSession, runtime.NumGoroutine())
	if perSession > 8*1024 {
		t.Logf("NOTE: each idle UDP session holds a full %d KiB receive buffer", u.bufSize/1024)
	}
}
