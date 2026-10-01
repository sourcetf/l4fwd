package engine

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// rawSockPairChurn opens and closes raw socket pairs and reports the handle
// count, so a socket leak in OpenRawSock/Close is caught immediately.
func TestRawSocketPairsDoNotLeakHandles(t *testing.T) {
	_, listen, _ := rawTestAddresses(t)

	base := osHandleCount()
	if base <= 0 {
		t.Skip("handle counting unavailable on this platform")
	}
	for n := 0; n < 60; n++ {
		proto := 100 + n%100
		capSock, err := netutil.OpenRawSock(netutil.RawSockOptions{Proto: proto, BindIP: listen, HeaderIncl: true})
		if err != nil {
			t.Fatalf("iteration %d: %v", n, err)
		}
		sndSock, err := netutil.OpenRawSock(netutil.RawSockOptions{Proto: proto, BindIP: listen, HeaderIncl: true, SendOnly: true})
		if err != nil {
			t.Fatalf("iteration %d send socket: %v", n, err)
		}
		_ = capSock.Close()
		_ = sndSock.Close()
	}
	time.Sleep(300 * time.Millisecond)
	after := osHandleCount()
	if after > base+10 {
		t.Fatalf("handle count grew from %d to %d over 60 socket pairs", base, after)
	}
	t.Logf("handles base=%d after=%d", base, after)
}

// TestRawListenerCyclesDoNotLeakHandles checks that repeatedly starting and
// stopping a raw rule settles instead of accumulating sockets.
func TestRawListenerCyclesDoNotLeakHandles(t *testing.T) {
	_, listen, target := rawTestAddresses(t)

	cycle := func(proto string) {
		rule := &config.Rule{ID: "cyl", Kind: config.KindRaw, Protocol: proto,
			ListenHost: listen.String(), TargetHost: target.String(), Enabled: true}
		if err := rule.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		l, err := NewRawListener(rule, config.Settings{}, stats.NewRuleStats(), quietLogger())
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if err := l.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
		l.Stop()
	}
	cycle("200") // warm up the runtime's thread pool
	time.Sleep(200 * time.Millisecond)
	base := osHandleCount()

	for i := 0; i < 10; i++ {
		cycle(fmt.Sprint(201 + i))
	}
	time.Sleep(300 * time.Millisecond)
	after := osHandleCount()
	if after > base+25 {
		t.Fatalf("handle count grew from %d to %d over 10 raw listener cycles", base, after)
	}
	t.Logf("handles base=%d after=%d", base, after)
}

// TestAllProtocolRuleReleasesGoroutines starts and stops the all-protocol rule
// (about 250 raw sockets) and checks the goroutines come back to the baseline:
// the capture loops must all observe the stop signal.
func TestAllProtocolRuleReleasesGoroutines(t *testing.T) {
	_, listen, target := rawTestAddresses(t)

	rule := &config.Rule{ID: "allres", Kind: config.KindRaw, Protocol: "all",
		ListenHost: listen.String(), ListenPort: freePort(t),
		TargetHost: target.String(), TargetPort: 9, Enabled: true}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	baseline := runtime.NumGoroutine()

	for i := 0; i < 2; i++ {
		ml, err := NewMultiListener(rule, config.Settings{DialTimeoutSec: 1}, stats.NewRuleStats(), quietLogger())
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if err := ml.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		done := make(chan struct{})
		go func() { ml.Stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("iteration %d: Stop did not return", i)
		}
	}
	// The runtime releases the poll threads lazily, so allow a generous settle.
	settled := runtime.NumGoroutine()
	for i := 0; i < 20 && settled > baseline+10; i++ {
		time.Sleep(200 * time.Millisecond)
		settled = runtime.NumGoroutine()
	}
	if settled > baseline+10 {
		t.Fatalf("goroutines stayed at %d (baseline %d) after the all-protocol rule stopped", settled, baseline)
	}
	t.Logf("goroutines baseline=%d settled=%d", baseline, settled)
}

// TestUDPRuleDoesNotLeakSockets churns client sessions through a UDP rule and
// checks the process handle count settles: every session owns an upstream socket
// that must be released when the session is reaped.
func TestUDPRuleDoesNotLeakSockets(t *testing.T) {
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
	rule := &config.Rule{ID: "udpres", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, UDPSessionTTLSec: 1}
	u := NewUDPListener(rule, config.Settings{UDPSessionTTLSec: 1, BufferKB: 64}, stats.NewRuleStats(), quietLogger())
	if err := u.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer u.Stop()

	round := func() {
		for i := 0; i < 10; i++ {
			c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				t.Fatalf("client %d: %v", i, err)
			}
			_, _ = c.Write([]byte("ping"))
			buf := make([]byte, 64)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Read(buf)
			_ = c.Close()
		}
		for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline) && u.Sessions() > 0; {
			time.Sleep(50 * time.Millisecond)
		}
	}
	round() // warm up
	base := osHandleCount()

	for i := 0; i < 4; i++ {
		round()
	}
	after := osHandleCount()
	if after > base+40 {
		t.Fatalf("handle count grew from %d to %d over 4 rounds of 10 UDP sessions", base, after)
	}
	t.Logf("handles base=%d after=%d sessions=%d", base, after, u.Sessions())
}
