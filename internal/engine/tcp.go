package engine

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// TCPListener relays a TCP port on the local machine to a fixed target. It is
// protocol agnostic: whatever bytes the client sends are forwarded verbatim.
type TCPListener struct {
	rule   *config.Rule
	set    config.Settings
	stats  *stats.RuleStats
	log    *logx.Logger
	ln     net.Listener
	closeO sync.Once
	done   chan struct{}
	wg     sync.WaitGroup

	// conns tracks live connections so Stop can close them: a connection that is
	// idle (or whose peer simply keeps the socket open) would otherwise keep
	// Stop waiting forever.
	connMu sync.Mutex
	conns  map[net.Conn]struct{}
	// stopping flips when Stop begins, so a connection accepted in that window is
	// refused instead of being registered after the sweep.
	stopping atomic.Bool

	active atomic.Int64
	denied atomic.Int64
}

// NewTCPListener prepares (but does not yet start) a TCP relay.
func NewTCPListener(rule *config.Rule, set config.Settings, st *stats.RuleStats, log *logx.Logger) *TCPListener {
	return &TCPListener{
		rule:  rule,
		set:   set,
		stats: st,
		log:   log,
		done:  make(chan struct{}),
		conns: map[net.Conn]struct{}{},
	}
}

// Start opens the listening socket and begins accepting.
func (t *TCPListener) Start() error {
	host := t.rule.ListenHost
	ln, err := netutil.ListenTCP(host, t.rule.ListenPort)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", netutil.HostPort(host, t.rule.ListenPort), err)
	}
	t.ln = ln
	t.log.Infof("tcp", "listening on %s -> %s:%d (rule %q)",
		ln.Addr(), t.rule.TargetHost, t.rule.TargetPort, t.rule.Name)

	t.wg.Add(1)
	go t.acceptLoop()
	return nil
}

func (t *TCPListener) acceptLoop() {
	defer t.wg.Done()
	var delay time.Duration
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.log.Warnf("tcp", "accept on %s failed: %v", t.ln.Addr(), err)
			// Back off briefly on resource exhaustion instead of spinning.
			delay = 5 * time.Millisecond
			if delay < time.Second {
				delay *= 2
			}
			select {
			case <-t.done:
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		if t.rule.MaxConns > 0 && t.active.Load() >= int64(t.rule.MaxConns) {
			t.denied.Add(1)
			t.stats.Error("connection refused: maxConns reached")
			_ = conn.Close()
			continue
		}
		t.wg.Add(1)
		go func(c net.Conn) {
			defer t.wg.Done()
			t.handle(c)
		}(conn)
	}
}

func (t *TCPListener) handle(client net.Conn) {
	defer client.Close()
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	t.track(client)
	defer t.untrack(client)

	t.active.Add(1)
	t.stats.ConnOpened()
	t.stats.ConnAccepted()
	defer func() {
		t.active.Add(-1)
		t.stats.ConnClosed()
	}()

	clientAddr := client.RemoteAddr().String()
	target := netutil.HostPort(t.rule.TargetHost, t.rule.TargetPort)
	upstream, err := netutil.DialTarget(t.rule.TargetHost, t.rule.TargetPort, t.rule.DialTimeout(t.set))
	if err != nil {
		t.stats.Error("dial " + target + ": " + err.Error())
		t.log.Warnf("tcp", "%s -> %s dial failed: %v", clientAddr, target, err)
		// Closing a socket that still holds unread data makes Windows send an
		// RST, which looks like a crash to the client. Drain it first so the
		// client sees a clean shutdown instead.
		drainAndClose(client, 250*time.Millisecond)
		return
	}
	t.track(upstream)
	defer t.untrack(upstream)
	if tc, ok := upstream.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	t.log.Debugf("tcp", "%s -> %s connected", clientAddr, target)
	relayPair(client, upstream, t.rule.IdleTimeout(t.set), t.stats)
	t.log.Debugf("tcp", "%s -> %s closed", clientAddr, target)
}

// track records a live connection so Stop can tear it down. It reports false
// when the listener is already stopping, in which case the caller must not use
// the connection: Stop has finished closing sockets and would never wait for it.
func (t *TCPListener) track(c net.Conn) bool {
	t.connMu.Lock()
	if t.stopping.Load() {
		t.connMu.Unlock()
		_ = c.Close()
		return false
	}
	if t.conns == nil {
		t.conns = map[net.Conn]struct{}{}
	}
	t.conns[c] = struct{}{}
	t.connMu.Unlock()
	return true
}

func (t *TCPListener) untrack(c net.Conn) {
	t.connMu.Lock()
	delete(t.conns, c)
	t.connMu.Unlock()
}

// closeTracked closes every connection currently registered.
func (t *TCPListener) closeTracked() {
	t.connMu.Lock()
	live := make([]net.Conn, 0, len(t.conns))
	for c := range t.conns {
		live = append(live, c)
	}
	t.connMu.Unlock()
	for _, c := range live {
		_ = c.Close()
	}
}

// Stop closes the listener and every active connection.
//
// Closing the connections is what makes Stop reliable: a client that keeps its
// socket open with no traffic (or a peer that never speaks) would leave the relay
// goroutines parked in Read, and Stop runs while the configuration is being
// reconciled, so it must not wait for a peer that may never talk again.
//
// The closing repeats until the goroutines have exited, because a connection can
// be accepted and registered between the listener closing and the first sweep;
// the stopping flag makes that window benign, and the loop guarantees the ones
// that slipped through are still closed.
func (t *TCPListener) Stop() {
	t.closeO.Do(func() {
		t.stopping.Store(true)
		close(t.done)
		if t.ln != nil {
			_ = t.ln.Close()
		}
	})
	finished := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(finished)
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		t.closeTracked()
		select {
		case <-finished:
			return
		case <-ticker.C:
		}
	}
}

// Active reports the number of live connections.
func (t *TCPListener) Active() int64 { return t.active.Load() }
