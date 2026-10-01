package engine

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/stats"
)

// countEngineGoroutines reports how many goroutines are parked in engine code.
func countEngineGoroutines() (int, string) {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	dump := string(buf[:n])
	count := strings.Count(dump, "l4fwd/internal/engine.")
	return count, dump
}

// TestListenersDoNotLeakGoroutines checks that starting and stopping rules
// repeatedly leaves no goroutines behind: a leaked relay goroutine keeps a
// socket open and would slowly exhaust the process.
func TestListenersDoNotLeakGoroutines(t *testing.T) {
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
			go func(c net.Conn) { defer c.Close(); _, _ = c.Write([]byte("x")) }(c)
		}
	}()

	store, err := config.NewStore(t.TempDir() + "/config.json")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	m := NewManager(quietLogger(), store.Get(), stats.NewSampler())

	port := freePort(t)
	rule := &config.Rule{ID: "leak", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true}

	// Warm up so the pool of runtime goroutines is established before counting.
	for i := 0; i < 3; i++ {
		if err := store.UpsertRule(rule); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		m.Apply(store.Get())
		if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			_ = c.Close()
		}
		time.Sleep(100 * time.Millisecond)
		if err := store.DeleteRule(rule.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		m.Apply(store.Get())
	}
	before, _ := countEngineGoroutines()

	// Churn: create, use, remove, many times.
	for i := 0; i < 25; i++ {
		r := *rule
		r.Enabled = true
		if err := store.UpsertRule(&r); err != nil {
			t.Fatalf("iteration %d upsert: %v", i, err)
		}
		m.Apply(store.Get())
		if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			_ = c.Close()
		}
		if err := store.DeleteRule(r.ID); err != nil {
			t.Fatalf("iteration %d delete: %v", i, err)
		}
		m.Apply(store.Get())
	}
	m.StopAll()

	// Give the runtime a moment to finish the last teardown, then compare.
	settled := 0
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		settled, _ = countEngineGoroutines()
		if settled <= before+2 {
			break
		}
	}
	if settled > before+2 {
		_, dump := countEngineGoroutines()
		var blocks []string
		for _, b := range strings.Split(dump, "\n\n") {
			if strings.Contains(b, "l4fwd/internal/engine") {
				blocks = append(blocks, b)
			}
		}
		t.Fatalf("goroutine count grew from %d to %d after 25 rule cycles:\n%s",
			before, settled, strings.Join(blocks, "\n---\n"))
	}
	t.Logf("engine goroutines before=%d after=%d", before, settled)
}
