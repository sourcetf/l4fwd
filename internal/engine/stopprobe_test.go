package engine

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// goroutineDump returns the engine frames of every goroutine, for hang reports.
func goroutineDump() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	var blocks []string
	for _, b := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(b, "l4fwd/internal/engine") || strings.Contains(b, "l4fwd/internal/netutil") {
			blocks = append(blocks, b)
		}
	}
	return strings.Join(blocks, "\n---\n")
}

// mustNotBlock fails the test with a goroutine dump when fn does not return in
// time. Stop runs while the configuration is reconciled, so a hung Stop freezes
// the whole tool; every stop path must be prompt.
func mustNotBlock(t *testing.T, what string, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s blocked for %s; engine goroutines:\n%s", what, limit, goroutineDump())
	}
}

// TestStopWithIdleConnection covers the case that made Stop hang: a client that
// connects and then says nothing, so both relay goroutines sit in Read.
func TestStopWithIdleConnection(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port

	port := freePort(t)
	rule := &config.Rule{ID: "idle", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true}
	l := NewTCPListener(rule, config.Settings{DialTimeoutSec: 2}, stats.NewRuleStats(), quietLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	time.Sleep(300 * time.Millisecond) // let the relay dial the backend

	start := time.Now()
	mustNotBlock(t, "TCP Stop", 5*time.Second, l.Stop)
	t.Logf("Stop returned in %v", time.Since(start).Round(time.Millisecond))
}

// TestStopTransparentWithIdleConnection is the same check for the transparent
// (TCP-shaped raw) listener.
func TestStopTransparentWithIdleConnection(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port

	port := freePort(t)
	rule := &config.Rule{ID: "trans-idle", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: port, TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 2}, stats.NewRuleStats(), quietLogger())
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	mustNotBlock(t, "transparent Stop", 5*time.Second, tr.Stop)
	t.Logf("Stop returned in %v", time.Since(start).Round(time.Millisecond))
}

// TestConcurrentApplyIsSerialised reproduces the manager race: the HTTP handler
// and the config watcher both call Apply, and without serialisation they would
// fight over the same port and could leak a listener that the manager no longer
// tracks.
func TestConcurrentApplyIsSerialised(t *testing.T) {
	store, err := config.NewStore(t.TempDir() + "/config.json")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	m := NewManager(quietLogger(), store.Get(), stats.NewSampler())
	defer func() {
		mustNotBlock(t, "StopAll", 10*time.Second, m.StopAll)
	}()

	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port

	port := freePort(t)
	// Every goroutine applies the same enabled rule, so whichever Apply runs
	// last the manager must end up with exactly one live listener.
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := config.Default()
			cfg.Rules = []*config.Rule{{
				ID: "race", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: port,
				TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
			}}
			m.Apply(cfg)
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// Exactly one instance must be tracked, and it must be serving.
	st, ok := m.Status("race")
	if !ok {
		t.Fatal("the rule is missing from the manager")
	}
	if !st.Running || st.Error != "" {
		t.Fatalf("rule not running: running=%v error=%q", st.Running, st.Error)
	}
	c, derr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if derr != nil {
		t.Fatalf("the rule reports running but the port is closed: %v", derr)
	}
	_ = c.Close()
	time.Sleep(200 * time.Millisecond)

	// A connection closed by the client must not stop the rule from being
	// removed, and the removal must be quick.
	mustNotBlock(t, "Apply(empty)", 10*time.Second, func() { m.Apply(config.Default()) })
	if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("the port still listens after the rule was removed")
	}
}

// TestTransparentListenerIsDualStack checks the TCP-shaped raw rule (the mode the
// dashboard picks for "tcp") also serves IPv6 loopback, because that is what
// `ssh localhost -p <port>` reaches for on Windows.
func TestTransparentListenerIsDualStack(t *testing.T) {
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
			go func(c net.Conn) { defer c.Close(); _, _ = c.Write([]byte("ok")) }(c)
		}
	}()

	port := freePort(t)
	rule := &config.Rule{ID: "dual", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "", ListenPort: port, TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 2}, stats.NewRuleStats(), quietLogger())
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()

	for _, target := range []string{netutil.HostPort("127.0.0.1", port), netutil.HostPort("::1", port)} {
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			// The gated listener opens an IPv6 socket too; if the host has no IPv6
			// at all the dial fails with a clear resolver error.
			t.Errorf("dial %s failed: %v", target, err)
			continue
		}
		buf := make([]byte, 8)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := c.Read(buf)
		t.Logf("%s -> %q", target, buf[:n])
		_ = c.Close()
	}
}
