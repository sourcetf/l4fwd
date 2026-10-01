package engine

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/stats"
)

func testLogger() *logx.Logger {
	l := logx.New(logx.Error, 200)
	l.SetOutput(io.Discard)
	return l
}

// freePort returns a localhost port that is free for both TCP and UDP.
//
// A TCP-only probe is not enough on Windows. The port number space is shared, and
// the system reserves ranges of it for itself (the "excluded port ranges" shown by
// `netsh int ipv4 show excludedportrange protocol=tcp`, typically held by Hyper-V
// or winnat). A bind into such a range fails with WSAEACCES — "An attempt was made
// to access a socket in a way forbidden by its access permissions" — even though a
// TCP listener had just released that very port number. Asking the kernel for a
// UDP port and then verifying both protocols keeps a test from failing for a
// reason that has nothing to do with the relay.
func freePort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		port := reserveUDPPort(t)
		if !portFreeForTCP(port) {
			continue
		}
		// Verify the UDP side explicitly: an excluded range refuses this bind.
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			continue
		}
		_ = pc.Close()
		return port
	}
	t.Fatal("找不到一个 TCP 和 UDP 都能绑定的本地端口")
	return 0
}

// reserveUDPPort asks the kernel for an unused local UDP port.
func reserveUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// portFreeForTCP reports whether a TCP listener can take the port.
func portFreeForTCP(port int) bool {
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", msg)
}

// TestTCPRelayEchoBinarySafe checks that a TCP rule forwards arbitrary bytes
// in both directions, including half close and binary payloads.
func TestTCPRelayEchoBinarySafe(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
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
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						if hc, ok := c.(halfCloser); ok {
							_ = hc.CloseWrite()
						}
						return
					}
				}
			}(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "t1", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
	}
	st := stats.NewRuleStats()
	l := NewTCPListener(rule, config.Settings{DialTimeoutSec: 5}, st, testLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer l.Stop()

	conn, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// Binary payload with NULs and high bytes.
	payload := make([]byte, 64*1024+123)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	payload[0], payload[1], payload[2] = 0x00, 0x00, 0xff

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d bytes differ", countDiff(got, payload))
	}

	// Half close: the echo server must see EOF and the relay must still deliver
	// the remaining bytes.
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF after half close, got %v", err)
	}

	snap := st.Snapshot()
	if snap.RxBytes < int64(len(payload)) {
		t.Fatalf("rx bytes = %d, want >= %d", snap.RxBytes, len(payload))
	}
	if snap.TxBytes < int64(len(payload)) {
		t.Fatalf("tx bytes = %d, want >= %d", snap.TxBytes, len(payload))
	}
	if snap.Conns < 1 {
		t.Fatalf("connection accounting off: conns=%d", snap.Conns)
	}
	// The active gauge drops once the handler finishes tearing the pair down,
	// which happens just after the client observes EOF.
	waitFor(t, 3*time.Second, func() bool { return st.Snapshot().Active == 0 }, "active gauge to reach zero")
}

func countDiff(a, b []byte) int {
	n := 0
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			n++
		}
	}
	return n
}

// TestTCPRelayConcurrentClients checks many simultaneous connections are
// handled independently.
func TestTCPRelayConcurrentClients(t *testing.T) {
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
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{ID: "t2", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true}
	st := stats.NewRuleStats()
	l := NewTCPListener(rule, config.Settings{DialTimeoutSec: 5}, st, testLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer l.Stop()

	const clients = 24
	var wg sync.WaitGroup
	errCh := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort))
			if err != nil {
				errCh <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer c.Close()
			msg := []byte(fmt.Sprintf("client-%02d-payload", id))
			if _, err := c.Write(msg); err != nil {
				errCh <- fmt.Errorf("client %d write: %w", id, err)
				return
			}
			buf := make([]byte, len(msg))
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c, buf); err != nil {
				errCh <- fmt.Errorf("client %d read: %w", id, err)
				return
			}
			if !bytes.Equal(buf, msg) {
				errCh <- fmt.Errorf("client %d got %q want %q", id, buf, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if v := st.Snapshot().Conns; v < clients {
		t.Fatalf("accepted %d connections, want >= %d", v, clients)
	}
}

// TestTCPRelayDialFailureClosingListener checks a missing backend does not
// break the listener.
func TestTCPRelayDialFailure(t *testing.T) {
	listenPort := freePort(t)
	deadPort := freePort(t) // nothing listens there
	rule := &config.Rule{ID: "t3", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: deadPort, Enabled: true}
	st := stats.NewRuleStats()
	l := NewTCPListener(rule, config.Settings{DialTimeoutSec: 2}, st, testLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer l.Stop()

	c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("hello"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	// The relay drains and closes cleanly, so the client observes EOF rather
	// than a reset.
	if _, err := c.Read(buf); err != io.EOF {
		t.Fatalf("expected EOF when the backend is unreachable, got %v", err)
	}
	if st.Snapshot().Errors == 0 {
		t.Fatal("dial failure must be counted as an error")
	}
}

// TestUDPRelayDatagramBoundaries verifies datagram framing is preserved and
// that replies reach the right client.
func TestUDPRelayDatagramBoundaries(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Echo with a marker so boundary mistakes are visible.
			out := append([]byte("echo:"), buf[:n]...)
			_, _ = backend.WriteToUDP(out, addr)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{ID: "u1", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, UDPSessionTTLSec: 2}
	st := stats.NewRuleStats()
	u := NewUDPListener(rule, config.Settings{UDPSessionTTLSec: 2}, st, testLogger())
	if err := u.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer u.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	messages := [][]byte{
		[]byte("one"),
		[]byte("two-two"),
		bytes.Repeat([]byte{0xff}, 1200),
		{0x00},
	}
	for i, msg := range messages {
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		buf := make([]byte, 65535)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		want := append([]byte("echo:"), msg...)
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d = %q, want %q", i, buf[:n], want)
		}
	}
	if v := st.Snapshot().RxPkts; v < int64(len(messages)) {
		t.Fatalf("rx packets = %d, want >= %d", v, len(messages))
	}
}

// TestUDPRelaySessionIsolation checks two clients get their own upstream
// sockets and never see each other's replies.
func TestUDPRelaySessionIsolation(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Answer on the socket we saw the request on: this is what tells
			// the relay which client to send the reply to.
			_, _ = backend.WriteToUDP(append([]byte("re:"), buf[:n]...), addr)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{ID: "u2", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, UDPSessionTTLSec: 1}
	st := stats.NewRuleStats()
	u := NewUDPListener(rule, config.Settings{UDPSessionTTLSec: 1}, st, testLogger())
	if err := u.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer u.Stop()

	a, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort})
	if err != nil {
		t.Fatalf("dial a: %v", err)
	}
	defer a.Close()
	b, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort})
	if err != nil {
		t.Fatalf("dial b: %v", err)
	}
	defer b.Close()

	if _, err := a.Write([]byte("alpha")); err != nil {
		t.Fatalf("a write: %v", err)
	}
	if _, err := b.Write([]byte("beta")); err != nil {
		t.Fatalf("b write: %v", err)
	}
	readOne := func(c *net.UDPConn, want string) {
		t.Helper()
		buf := make([]byte, 256)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("client received %q, want %q", got, want)
		}
	}
	readOne(a, "re:alpha")
	readOne(b, "re:beta")

	waitFor(t, 3*time.Second, func() bool { return u.Sessions() == 2 }, "two sessions")
	// After the TTL both sessions must be reaped.
	waitFor(t, 5*time.Second, func() bool { return u.Sessions() == 0 }, "sessions to expire")
	if st.Snapshot().Active != 0 {
		t.Fatalf("active gauge = %d after expiry", st.Snapshot().Active)
	}
}

// TestUDPRelayLargeDatagram makes sure a 64 KiB datagram survives the relay.
func TestUDPRelayLargeDatagram(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteToUDP(buf[:n], addr)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{ID: "u3", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true, UDPSessionTTLSec: 2}
	u := NewUDPListener(rule, config.Settings{UDPSessionTTLSec: 2, BufferKB: 64}, stats.NewRuleStats(), testLogger())
	if err := u.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer u.Stop()

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 60000)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 65535)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(payload) || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("large datagram mismatch: got %d bytes", n)
	}
}

// TestListenerStopIsClean ensures Stop unblocks accept/read loops.
func TestListenerStopIsClean(t *testing.T) {
	listenPort := freePort(t)
	tcpRule := &config.Rule{ID: "s1", Kind: config.KindTCP, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: freePort(t), Enabled: true}
	st := stats.NewRuleStats()
	tl := NewTCPListener(tcpRule, config.Settings{DialTimeoutSec: 1}, st, testLogger())
	if err := tl.Start(); err != nil {
		t.Fatalf("tcp start: %v", err)
	}
	done := make(chan struct{})
	go func() { tl.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("TCP listener Stop did not return")
	}

	udpPort := freePort(t)
	udpRule := &config.Rule{ID: "s2", Kind: config.KindUDP, ListenHost: "127.0.0.1", ListenPort: udpPort,
		TargetHost: "127.0.0.1", TargetPort: freePort(t), Enabled: true}
	ul := NewUDPListener(udpRule, config.Settings{}, stats.NewRuleStats(), testLogger())
	if err := ul.Start(); err != nil {
		t.Fatalf("udp start: %v", err)
	}
	done2 := make(chan struct{})
	go func() { ul.Stop(); close(done2) }()
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("UDP listener Stop did not return")
	}
}

// TestTransparentTCPListenerForwards checks the transparent listener relays a
// real TCP conversation to the target port and counts the connection.
func TestTransparentTCPListenerForwards(t *testing.T) {
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
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "trans1", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	st := stats.NewRuleStats()
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 3}, st, quietLogger())
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()

	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()

	msg := []byte("transparent-relay-payload")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
	if v := st.Snapshot().Conns; v < 1 {
		t.Fatalf("connections counted = %d", v)
	}
}

// TestTransparentTCPListenerRefusesWhenTargetDown checks that with gating on,
// a connect attempt fails while the target is unreachable, so a tcping style
// probe reports the target's state rather than the forwarder's.
func TestTransparentTCPListenerRefusesWhenTargetDown(t *testing.T) {
	listenPort := freePort(t)
	deadPort := freePort(t) // nothing listens there
	rule := &config.Rule{
		ID: "trans2", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: deadPort, Enabled: true, DialTimeoutSec: 1,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	st := stats.NewRuleStats()
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 1}, st, quietLogger())
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()

	if !tr.gated {
		t.Skip("SO_CONDITIONAL_ACCEPT unavailable on this host; gating falls back to a plain listener")
	}

	start := time.Now()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
	if err == nil {
		_ = c.Close()
		t.Fatal("connect must not succeed while the target is unreachable")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("refusal took %v", elapsed)
	}
	waitFor(t, 2*time.Second, func() bool { return tr.Denied() >= 1 }, "a denied connection to be counted")
}
