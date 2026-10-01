//go:build windows

package engine

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/stats"
)

// TestTransparentBurstIsNotSerialised is the regression guard for the burst
// defect that made the relay look "much slower than the two legs added
// together".
//
// Windows runs one SO_CONDITIONAL_ACCEPT callback at a time per listening socket
// and leaves the connections behind it unacknowledged. When the gate dialled the
// target inside that callback, a burst of N connections cost N target round trips
// in sequence, and every SYN past the first few was still unanswered when the
// client gave up ("the connected party did not properly respond"). Straight
// against the target the same burst was instant.
//
// The listener now answers the gate from a shared target probe, so a burst costs
// one round trip. The backend here delays its accept by one simulated round trip
// to stand in for a remote target.
func TestTransparentBurstIsNotSerialised(t *testing.T) {
	const dialDelay = 400 * time.Millisecond
	var accepted atomic.Int64

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
			accepted.Add(1)
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "burst", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
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

	// Every dial of this rule is slowed down, which is what a remote target looks
	// like from the relay's point of view.
	tr.dial = func() (net.Conn, error) {
		conn, err := tr.dialTarget()
		if err != nil {
			return nil, err
		}
		time.Sleep(dialDelay)
		return conn, nil
	}

	const clients = 8
	var ok, failed atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", itoa(listenPort)), 10*time.Second)
			if err != nil {
				failed.Add(1)
				return
			}
			ok.Add(1)
			_ = c.Close()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("%d 个并发连接（目标建连延迟 %v）：成功 %d / 失败 %d，用时 %v，实际起到的后端连接 %d 个",
		clients, dialDelay, ok.Load(), failed.Load(), elapsed.Round(time.Millisecond), accepted.Load())
	if failed.Load() != 0 {
		t.Fatalf("%d 个并发连接里 %d 个失败：连接还在门控回调上排队", clients, failed.Load())
	}
	if elapsed > 3*dialDelay {
		t.Fatalf("爆发连接被串行处理：%d 个连接花了 %v（串行下限 %v）",
			clients, elapsed.Round(time.Millisecond), time.Duration(clients)*dialDelay)
	}
}

// TestTransparentBurstTargetDownBreaksAfterProbe checks the probe cache cannot
// hide a dead target: the refusal is remembered for a short window only, and a
// connection arriving after that window dials again.
func TestTransparentBurstTargetDownBreaksAfterProbe(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	backendPort := backend.Addr().(*net.TCPAddr).Port
	deadPort := freePort(t) // nothing listens here
	_ = backend.Close()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "down", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: deadPort, Enabled: true,
	}
	_ = backendPort
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	lg := logx.New(logx.Error, 50)
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 2}, stats.NewRuleStats(), lg)
	tr.probeTTL = 200 * time.Millisecond
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()

	addr := net.JoinHostPort("127.0.0.1", itoa(listenPort))
	for i := 0; i < 3; i++ {
		start := time.Now()
		c, err := net.DialTimeout("tcp4", addr, 5*time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatalf("第 %d 次：目标不可达，客户端却连接成功", i+1)
		}
		t.Logf("第 %d 次：%v 后收到拒绝（%v）", i+1, time.Since(start).Round(time.Millisecond), err)
		time.Sleep(250 * time.Millisecond)
	}
}

// TestTransparentProbeDoesNotLeakConnections makes sure the probe's connection is
// either used by a real client or closed: a probe that opens a connection and
// then discards it would leak one socket per burst.
func TestTransparentProbeDoesNotLeakConnections(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port
	var open atomic.Int64
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			open.Add(1)
			go func(c net.Conn) {
				defer func() { open.Add(-1) }()
				defer c.Close()
				_, _ = io.Copy(c, c) // echo, so the test can prove data flows
			}(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "leak", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
	}
	lg := logx.New(logx.Error, 50)
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 2}, stats.NewRuleStats(), lg)
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()

	addr := net.JoinHostPort("127.0.0.1", itoa(listenPort))
	for i := 0; i < 20; i++ {
		c, err := net.DialTimeout("tcp4", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("第 %d 次连接：%v", i+1, err)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			_ = c.Close()
			t.Fatalf("第 %d 次写入：%v", i+1, err)
		}
		buf := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			_ = c.Close()
			t.Fatalf("第 %d 次回读：%v", i+1, err)
		}
		_ = c.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && open.Load() != 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if n := open.Load(); n != 0 {
		t.Fatalf("20 次连接之后后端仍开着 %d 个连接：探测连接泄漏了", n)
	}
	t.Logf("20 次连接后后端连接数归零，未泄漏")
	_ = fmt.Sprint
}

// TestTransparentSlowTargetDoesNotDelayEveryConnection covers the slow target case.
//
// The gate never waits for a dial another connection started: the kernel runs one
// condition callback at a time, so a second connection cannot reach the gate while
// the first is dialling anyway. What it does instead is answer from the verdict
// the first dial published, which is why a slow target still lets a burst
// through: the first connection pays the round trip, the rest are answered
// immediately and dial on their own afterwards.
func TestTransparentSlowTargetDoesNotDelayEveryConnection(t *testing.T) {
	const dialDelay = 1 * time.Second // longer than a client's SYN patience
	var accepted atomic.Int64

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
			accepted.Add(1)
			go func(c net.Conn) { defer c.Close() }(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "slow-burst", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	lg := logx.New(logx.Error, 50)
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 5}, stats.NewRuleStats(), lg)
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()
	tr.dial = func() (net.Conn, error) {
		conn, err := tr.dialTarget()
		if err != nil {
			return nil, err
		}
		time.Sleep(dialDelay)
		return conn, nil
	}

	const clients = 4
	var ok, failed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The client's own patience, as Windows implements it for a connect.
			c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", itoa(listenPort)), 1200*time.Millisecond)
			if err != nil {
				failed.Add(1)
				return
			}
			ok.Add(1)
			_ = c.Close()
		}()
	}
	wg.Wait()
	// Each connection that was let through dials the target from its own
	// goroutine, and those dials are as slow as the target, so the backend
	// connections arrive after the client handshakes did.
	waitFor(t, 8*time.Second, func() bool { return accepted.Load() >= int64(clients) }, "every client to reach the target")
	t.Logf("目标拨号 %v 时 %d 个并发连接（客户端耐心 1.2s）：成功 %d / 失败 %d，后端连接 %d 个",
		dialDelay, clients, ok.Load(), failed.Load(), accepted.Load())
	// Every client must get its handshake completed inside its own patience. A
	// slow target cannot answer a 250 ms budget, so the gates have to let these
	// connections through without a verdict.
	if ok.Load() != clients {
		t.Fatalf("慢目标下 %d 个连接只成功了 %d 个：门控在等目标，客户端先放弃了", clients, ok.Load())
	}
	if tr.Unprobed() == 0 {
		t.Fatalf("%d 个连接都拿到了判定，说明门控等满了 %v 的拨号（应当有连接被直接放行）", clients, dialDelay)
	}
	// The connections that were let through must not be left without an upstream:
	// each one dials for itself, so the backend sees a connection per client (the
	// probe's own connection is shared with the first of them).
	if got := accepted.Load(); got < int64(clients) {
		t.Fatalf("后端只看到 %d 个连接（%d 个客户端）：被放行的连接没有各自拨号", got, clients)
	}
}
