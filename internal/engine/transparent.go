package engine

import (
	"errors"
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

// TransparentTCPListener forwards TCP-shaped traffic to a real TCP target.
//
// It exists because Windows refuses to let a raw socket carry IPPROTO_TCP:
// binding a raw TCP socket fails with WSAEINVAL and an injected SYN is rejected
// with the same error. Any tool that crafts TCP itself — a "tcping" probe that
// only performs a connect, a custom handshake, a non standard TCP client — can
// therefore not be relayed packet by packet. What such traffic actually needs is
// for the target address and port to be reached, so this listener stands in for
// them and opens a real TCP connection from this machine to the target.
//
// With Gated set (the default for TCP-shaped rules) the connection is only
// completed once the target has accepted, so a connect probe reports the
// target's real state instead of a false success.
type TransparentTCPListener struct {
	rule  *config.Rule
	set   config.Settings
	stats *stats.RuleStats
	log   *logx.Logger

	gated bool
	ln    net.Listener
	gate  *netutil.GatedListener

	done   chan struct{}
	closeO sync.Once
	wg     sync.WaitGroup

	// connMu/conns track live connections so Stop can close them: an idle client
	// would otherwise keep the relay goroutines blocked in Read while Stop waits.
	connMu sync.Mutex
	conns  map[net.Conn]struct{}
	// stopping flips when Stop begins so a connection accepted in that window is
	// closed instead of being registered after the final sweep.
	stopping atomic.Bool

	active atomic.Int64

	denied atomic.Int64

	// probe is the shared answer to "is the target reachable right now".
	//
	// It exists because the gate runs inside the handshake, and Windows lets only
	// one condition callback run at a time per listening socket: while the first
	// connection of a burst dials the target, every other SYN goes
	// unacknowledged, and a client gives up after about a second. Dialling once
	// and letting the rest of the burst share that answer keeps a burst to one
	// target round trip instead of one per connection.
	//
	// probeTTL is how long a *successful* verdict answers for. It is deliberately
	// short: while it holds, connections are completed without waiting for a dial,
	// so a target that went away in the meantime is discovered by the dial that
	// follows the accept (and the client sees a close) rather than by a refusal.
	probeMu  sync.Mutex
	probe    *targetProbe
	probeTTL time.Duration

	// unprobed counts connections that were completed without a verdict — either
	// because the target answered too slowly or because another connection was
	// already probing. It is worth surfacing on the dashboard: a non-zero value
	// means the "refuse when the target is down" guarantee is being traded for the
	// client's handshake, which is the right call but not invisible.
	unprobed atomic.Int64

	// dial is the upstream dialer. It is a field so tests can make a target look
	// remote without a real network delay.
	dial func() (net.Conn, error)
}

// targetProbe is a verdict about the target plus, when the dial succeeded, the
// connection it produced.
type targetProbe struct {
	done     chan struct{}
	ok       bool
	err      error
	at       time.Time
	upstream net.Conn
	claimed  bool
}

// claim hands the probed connection to one caller. A probe is paid for once: the
// connection it opened becomes the upstream of the first connection that asked,
// and the rest of the burst dial their own after being accepted.
func (p *targetProbe) claim() net.Conn {
	if p.claimed || p.upstream == nil {
		return nil
	}
	p.claimed = true
	return p.upstream
}

// NewTransparentTCPListener prepares the listener.
func NewTransparentTCPListener(rule *config.Rule, set config.Settings, st *stats.RuleStats, log *logx.Logger) *TransparentTCPListener {
	t := &TransparentTCPListener{
		rule:     rule,
		set:      set,
		stats:    st,
		log:      log,
		gated:    rule.GateOnTarget(),
		done:     make(chan struct{}),
		conns:    map[net.Conn]struct{}{},
		probeTTL: targetProbeTTL,
	}
	t.dial = t.dialTarget
	return t
}

// targetProbeTTL is how long a successful probe answers for: inside this window a
// new connection is completed immediately and dialled afterwards. It has to stay
// short — a target can go away at any moment — and it only covers the burst case
// (a browser opening its parallel connections, a client reconnecting).
const targetProbeTTL = 2 * time.Second

// Start binds the local port and begins accepting.
func (t *TransparentTCPListener) Start() error {
	host := t.rule.ListenHost
	if netutil.IsWildcardHost(host) {
		host = ""
	}
	addr := netutil.HostPort(host, t.rule.ListenPort)
	target := netutil.HostPort(t.rule.TargetHost, t.rule.TargetPort)

	if t.gated {
		gate, err := netutil.ListenGated(t.rule.ListenHost, t.rule.ListenPort)
		if err != nil {
			// SO_CONDITIONAL_ACCEPT is not always available (some drivers, some
			// RDP/loopback configurations reject it); fall back to a plain
			// listener, which still forwards, just without truthful probing.
			t.log.Warnf("raw", "无法启用目标探测门控（%v），退回普通监听：连接建立不再等待目标确认", err)
			t.gated = false
		} else {
			t.gate = gate
		}
	}
	if !t.gated {
		ln, err := netutil.ListenTCP(t.rule.ListenHost, t.rule.ListenPort)
		if err != nil {
			return fmt.Errorf("listen tcp(transparent) %s: %w", addr, err)
		}
		t.ln = ln
	}

	mode := "普通监听"
	if t.gated {
		mode = "目标门控"
	}
	t.log.Infof("raw", "TCP 透明转发监听 %s -> %s（%s，规则 %q）：原始套接字无法处理 TCP，改由内核协议栈建连到目标",
		addr, target, mode, t.rule.Name)

	if t.gated {
		// WSAAccept handles one connection per call and the kernel runs one gate
		// at a time, so several workers park in it at once; that is what lets a
		// burst of connections be completed without queueing behind each other.
		workers := transparentAcceptWorkers
		if t.rule.MaxConns > 0 && t.rule.MaxConns < workers {
			workers = t.rule.MaxConns
		}
		if workers < 1 {
			workers = 1
		}
		for i := 0; i < workers; i++ {
			t.wg.Add(1)
			go t.gatedAcceptLoop()
		}
		return nil
	}

	t.wg.Add(1)
	go t.acceptLoop()
	return nil
}

// transparentAcceptWorkers is how many gated accepts run at once.
const transparentAcceptWorkers = 16

// gatedAcceptLoop accepts clients through the conditional-accept socket. The
// gate answers from the listener's shared knowledge of the target, so the
// handshake completes without waiting for a dial of its own.
func (t *TransparentTCPListener) gatedAcceptLoop() {
	defer t.wg.Done()
	for {
		client, err := t.gate.Accept(t.gateAnswer)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A gate rejection is normal operation (the target is down), not a
			// listener failure: count it and keep serving other clients.
			t.denied.Add(1)
			t.stats.Error("target unreachable: " + err.Error())
			t.log.Debugf("raw", "拒绝连接：目标不可达（%v）", err)
			continue
		}
		if t.rule.MaxConns > 0 && t.active.Load() >= int64(t.rule.MaxConns) {
			t.denied.Add(1)
			t.stats.Error("connection refused: maxConns reached")
			_ = client.Close()
			continue
		}
		t.wg.Add(1)
		go func(c net.Conn) {
			defer t.wg.Done()
			t.handle(c)
		}(client)
	}
}

// acceptLoop accepts clients on the plain (non gated) listener.
func (t *TransparentTCPListener) acceptLoop() {
	defer t.wg.Done()
	var delay time.Duration
	for {
		client, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.log.Warnf("raw", "accept on %s failed: %v", t.ln.Addr(), err)
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
			_ = client.Close()
			continue
		}
		t.wg.Add(1)
		go func(c net.Conn) {
			defer t.wg.Done()
			t.handle(c)
		}(client)
	}
}

// dialTarget opens the upstream connection to the rule's target. It is used
// directly when the gate let a connection through without a probe.
func (t *TransparentTCPListener) dialTarget() (net.Conn, error) {
	target := netutil.HostPort(t.rule.TargetHost, t.rule.TargetPort)
	conn, err := netutil.DialTarget(t.rule.TargetHost, t.rule.TargetPort, t.rule.DialTimeout(t.set))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	tuneUpstream(conn)
	return conn, nil
}

// gateAnswer is what the handshake gate is allowed to do: decide from what the
// listener already knows, never wait.
//
// The gate must return promptly — see netutil.GatedListener — so it answers in
// one of three ways:
//
//	the target was reachable      → complete the handshake now, using the probed
//	                                connection if it is still unclaimed
//	the target was unreachable    → refuse the connection (the probe answered
//	                                less than targetProbeTTL ago)
//	nothing known yet             → dial once, and let the whole burst share the
//	                                answer; the very first connection carries
//	                                the probe's own connection, the others dial
//	                                after being accepted
//
// gateAnswer is what the handshake gate is allowed to do: answer from what the
// listener already knows, start a dial when it knows nothing, and never hold a
// client's handshake longer than gateBudget.
//
// Why the budget is not optional: the kernel runs one condition callback at a
// time per listening socket, so a burst is decided one connection at a time. A
// gate that waited for a full target dial each time would make a burst of N
// connections take N round trips, and Windows fails a connect whose handshake
// stays incomplete for about a second — measured with a 1 s target, three of
// four concurrent connections died that way.
//
// The wait is therefore bounded twice over:
//
//   - it is at most gateBudget, and
//   - only the connection that started the probe waits at all. The rest are
//     accepted immediately and dial for themselves, because callbacks are serial:
//     a per-connection wait would accumulate, and the tail of a burst would still
//     exceed the client's patience (four connections × 250 ms is a second).
//
// So the gate answers in one of three ways:
//
//	a fresh verdict exists  → answer with it, no waiting at all
//	nothing in flight       → start a dial, wait gateBudget for it, answer with
//	                          the result if it arrives (refuse when the target is
//	                          unreachable, accept with the probed connection
//	                          otherwise) or accept now if it does not
//	a dial is in flight     → accept now and let this connection dial itself
//
// A dial that outlives the budget keeps running in the background and publishes
// its verdict, so later connections are answered from the cache.
func (t *TransparentTCPListener) gateAnswer() (net.Conn, error) {
	t.probeMu.Lock()
	if pr := t.probe; pr != nil && isClosed(pr.done) && time.Since(pr.at) < t.probeTTL {
		up := pr.claim()
		ok, err := pr.ok, pr.err
		t.probeMu.Unlock()
		if !ok {
			return nil, err
		}
		// up may be nil: the connection that paid for the probe took it, and the
		// rest dial their own after being accepted.
		return up, nil
	}
	pr := t.probe
	started := false
	if pr == nil || isClosed(pr.done) {
		// Nothing in flight: start one. It runs in the background so the budget
		// below is about the client's patience, not about the dial's duration.
		pr = &targetProbe{done: make(chan struct{})}
		t.probe = pr
		started = true
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.runProbe(pr)
		}()
	}
	t.probeMu.Unlock()

	if !started {
		// Another connection is already probing. Waiting for it would make this
		// handshake (and every one behind it) pay the target's latency again, so
		// the connection is accepted now and dials the target itself.
		t.unprobed.Add(1)
		return nil, nil
	}

	timer := time.NewTimer(gateBudget)
	defer timer.Stop()
	select {
	case <-pr.done:
		up := pr.claim()
		ok, err := pr.ok, pr.err
		if !ok {
			return nil, err
		}
		return up, nil
	case <-timer.C:
		// The target is slow to answer. Complete the handshake now and let this
		// connection dial for itself, rather than leaving the client to time out.
		t.unprobed.Add(1)
		t.stats.Error("target slow: connection completed without waiting for the probe")
		return nil, nil
	}
}

// runProbe dials the target and publishes the verdict for the connections behind
// this one.
func (t *TransparentTCPListener) runProbe(pr *targetProbe) {
	conn, err := t.dial()
	t.probeMu.Lock()
	if err != nil {
		pr.err = err
	} else {
		pr.ok = true
		pr.upstream = conn
	}
	pr.at = time.Now()
	close(pr.done)
	t.probeMu.Unlock()
}

// gateBudget is how long a handshake may wait for the target. It has to stay well
// under the roughly one second Windows gives a connecting client, so that the
// connection is completed even when the target is slow to answer.
const gateBudget = 250 * time.Millisecond

// isClosed reports whether ch has been closed already.
func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// tuneUpstream applies the socket options the relay needs on the target side.
func tuneUpstream(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func (t *TransparentTCPListener) handle(client net.Conn) {
	defer client.Close()
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if !t.track(client) {
		return // the listener is stopping; the connection was closed for us
	}
	defer t.untrack(client)

	t.active.Add(1)
	t.stats.ConnAccepted()
	t.stats.ConnOpened()
	defer func() {
		t.active.Add(-1)
		t.stats.ConnClosed()
	}()

	target := netutil.HostPort(t.rule.TargetHost, t.rule.TargetPort)

	// With gating, the upstream is usually attached by the handshake gate; when
	// the gate accepted on the strength of a recent probe that another connection
	// already claimed, this connection dials its own.
	upstream := netutil.UpstreamOf(client)
	if upstream == nil {
		var err error
		upstream, err = t.dial()
		if err != nil {
			t.stats.Error(err.Error())
			t.log.Warnf("raw", "%s -> %s 建连失败: %v", client.RemoteAddr(), target, err)
			drainAndClose(client, 250*time.Millisecond)
			return
		}
	}
	if !t.track(upstream) {
		return
	}
	defer t.untrack(upstream)
	t.log.Debugf("raw", "TCP 透明转发 %s -> %s 已建连", client.RemoteAddr(), target)
	relayPair(client, upstream, t.rule.IdleTimeout(t.set), t.stats)
}

// track records a live connection so Stop can tear it down. It reports false
// when the listener is already stopping, in which case the connection has been
// closed and must not be used.
func (t *TransparentTCPListener) track(c net.Conn) bool {
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

func (t *TransparentTCPListener) untrack(c net.Conn) {
	t.connMu.Lock()
	delete(t.conns, c)
	t.connMu.Unlock()
}

func (t *TransparentTCPListener) closeTracked() {
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

// Stop closes the listener and all connections. Live connections are closed
// explicitly, and the sweep repeats until the relay goroutines have exited: a
// connection accepted while Stop was running would otherwise keep the process
// waiting on a peer that may never speak again.
func (t *TransparentTCPListener) Stop() {
	t.closeO.Do(func() {
		t.stopping.Store(true)
		close(t.done)
		if t.gate != nil {
			_ = t.gate.Close()
		}
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

// Active reports live connections.
func (t *TransparentTCPListener) Active() int64 { return t.active.Load() }

// Unprobed reports how many connections were completed without waiting for a
// verdict about the target.
func (t *TransparentTCPListener) Unprobed() int64 { return t.unprobed.Load() }

// Denied reports connection attempts refused because the target was down.
func (t *TransparentTCPListener) Denied() int64 { return t.denied.Load() }
