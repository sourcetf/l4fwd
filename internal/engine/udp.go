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

// udpSession is one client conversation. Each client gets its own upstream
// socket so replies can be routed back unambiguously.
type udpSession struct {
	client   *net.UDPAddr
	upstream *net.UDPConn
	lastSeen atomic.Int64 // unix nanos
	pktsIn   atomic.Int64
	pktsOut  atomic.Int64
	closed   atomic.Bool
}

// UDPListener relays a UDP port. Datagram boundaries and payloads are passed
// through untouched, so any UDP based protocol (including non standard ones)
// works as long as its addressing fits inside the datagrams.
type UDPListener struct {
	rule  *config.Rule
	set   config.Settings
	stats *stats.RuleStats
	log   *logx.Logger

	conn   *net.UDPConn
	done   chan struct{}
	closeO sync.Once
	wg     sync.WaitGroup

	mu      sync.Mutex
	session map[string]*udpSession
	active  atomic.Int64
	// denied counts clients refused because the session table was full.
	denied atomic.Int64
	ttl    time.Duration
	// bufSize is the receive buffer of a session's upstream socket. It is kept
	// per session, so the session cap below is what bounds memory: an unprotected
	// UDP relay would allocate one buffer per client address a flood can invent.
	bufSize int
	// limit is the hard ceiling on concurrent sessions. Unlike rule.MaxConns it can
	// never be switched off, so a spoofed-source flood cannot exhaust memory.
	limit int
}

// UDP session limits. A session holds a socket, a goroutine and a receive
// buffer, so the cap is what keeps a flood from exhausting memory.
const (
	// udpSessionMemoryBudget is the memory the session buffered receive data is
	// allowed to occupy when the rule does not set maxConns. Measured cost is a
	// few hundred bytes of bookkeeping plus one u.bufSize buffer per session.
	udpSessionMemoryBudget = 64 << 20 // 64 MiB
	// udpSessionMinDefault keeps the default usable for legitimate traffic even
	// when the buffer size would make the budget very small.
	udpSessionMinDefault = 256
	// udpSessionMaxCeiling bounds an explicit maxConns from the config so a typo
	// cannot ask for a million sessions.
	udpSessionMaxCeiling = 65536
)

// NewUDPListener prepares a UDP relay.
func NewUDPListener(rule *config.Rule, set config.Settings, st *stats.RuleStats, log *logx.Logger) *UDPListener {
	buf := set.BufferKB * 1024
	if buf < 65535 {
		buf = 65535 // a UDP datagram can be up to 64 KiB
	}
	limit := udpSessionMemoryBudget / buf
	if limit < udpSessionMinDefault {
		limit = udpSessionMinDefault
	}
	if rule.MaxConns > 0 {
		limit = rule.MaxConns
	}
	if limit > udpSessionMaxCeiling {
		limit = udpSessionMaxCeiling
	}
	return &UDPListener{
		rule:    rule,
		set:     set,
		stats:   st,
		log:     log,
		done:    make(chan struct{}),
		session: map[string]*udpSession{},
		ttl:     rule.UDPSessionTTL(set),
		bufSize: buf,
		limit:   limit,
	}
}

// Start binds the UDP port and starts the session reaper.
func (u *UDPListener) Start() error {
	conn, err := netutil.ListenUDP(u.rule.ListenHost, u.rule.ListenPort)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", netutil.HostPort(u.rule.ListenHost, u.rule.ListenPort), err)
	}
	_ = conn.SetReadBuffer(u.bufSize)
	u.conn = conn
	u.log.Infof("udp", "listening on %s -> %s:%d (rule %q, session ttl %s)",
		conn.LocalAddr(), u.rule.TargetHost, u.rule.TargetPort, u.rule.Name, u.ttl)

	u.wg.Add(2)
	go u.readLoop()
	go u.reapLoop()
	return nil
}

func (u *UDPListener) readLoop() {
	defer u.wg.Done()
	buf := make([]byte, u.bufSize)
	for {
		select {
		case <-u.done:
			return
		default:
		}
		n, clientAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-u.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			u.log.Warnf("udp", "read on %s failed: %v", u.conn.LocalAddr(), err)
			u.stats.Error("read: " + err.Error())
			continue
		}
		u.stats.RecordPacket(stats.DirIn, int64(n), true)
		// The datagram is written out synchronously and the client address is
		// copied by ReadFromUDP into its own allocation, so the receive buffer can
		// be reused for the next datagram instead of copying every payload.
		u.dispatch(clientAddr, buf[:n])
	}
}

// dispatch forwards one datagram to the per-client upstream socket, creating
// the session when this client is seen for the first time.
func (u *UDPListener) dispatch(clientAddr *net.UDPAddr, payload []byte) {
	key := clientAddr.String()
	u.mu.Lock()
	s := u.session[key]
	u.mu.Unlock()

	if s == nil {
		ns, err := u.newSession(clientAddr)
		if err != nil {
			u.stats.Error("open upstream: " + err.Error())
			u.log.Warnf("udp", "cannot reach %s:%d for client %s: %v", u.rule.TargetHost, u.rule.TargetPort, key, err)
			return
		}
		s = ns
	}
	s.lastSeen.Store(time.Now().UnixNano())
	if _, err := s.upstream.Write(payload); err != nil {
		u.stats.Error("upstream write: " + err.Error())
		u.closeSession(key, s, "write failed")
		return
	}
	s.pktsIn.Add(1)
}

func (u *UDPListener) newSession(clientAddr *net.UDPAddr) (*udpSession, error) {
	up, err := netutil.DialTargetUDP(u.rule.TargetHost, u.rule.TargetPort)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	_ = up.SetWriteBuffer(u.bufSize)
	s := &udpSession{client: clientAddr, upstream: up}
	s.lastSeen.Store(time.Now().UnixNano())

	key := clientAddr.String()
	u.mu.Lock()
	if old, ok := u.session[key]; ok {
		// Another goroutine won the race; keep the existing session.
		u.mu.Unlock()
		_ = up.Close()
		return old, nil
	}
	select {
	case <-u.done:
		// The listener stopped while this datagram was in flight; do not register
		// a session that nobody would ever close.
		u.mu.Unlock()
		_ = up.Close()
		return nil, net.ErrClosed
	default:
	}
	// The cap is checked while holding the lock that guards the map, so a burst of
	// new clients cannot slip past it and grow the table past the limit.
	if u.limit > 0 && len(u.session) >= u.limit {
		u.mu.Unlock()
		_ = up.Close()
		u.denied.Add(1)
		u.stats.Drop(1)
		u.stats.Error(fmt.Sprintf("会话数达到上限 %d，拒绝来自 %s 的新会话", u.limit, key))
		u.log.Warnf("udp", "session limit %d reached, dropping new client %s", u.limit, key)
		return nil, fmt.Errorf("session limit %d reached", u.limit)
	}
	u.session[key] = s
	u.mu.Unlock()

	// Register with the wait group while the session is already visible, so Stop
	// cannot miss it. The count is released by the reply loop, which is started
	// below on every path that keeps the session.
	u.wg.Add(1)
	started := false
	defer func() {
		if !started {
			u.wg.Done()
		}
	}()

	u.active.Add(1)
	u.stats.ConnOpened()
	u.stats.ConnAccepted()
	u.log.Debugf("udp", "new session %s -> %s:%d", key, u.rule.TargetHost, u.rule.TargetPort)

	started = true
	go u.replyLoop(key, s)
	return s, nil
}

func (u *UDPListener) replyLoop(key string, s *udpSession) {
	defer u.wg.Done()
	buf := make([]byte, u.bufSize)
	for {
		select {
		case <-u.done:
			return
		default:
		}
		// Sessions die when idle so abandoned clients do not pin sockets.
		_ = s.upstream.SetReadDeadline(time.Now().Add(u.ttl))
		n, err := s.upstream.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if time.Since(time.Unix(0, s.lastSeen.Load())) >= u.ttl {
					u.closeSession(key, s, "idle timeout")
					return
				}
				continue
			}
			select {
			case <-u.done:
				return
			default:
			}
			u.closeSession(key, s, "read: "+err.Error())
			return
		}
		if n <= 0 {
			continue
		}
		if _, err := u.conn.WriteToUDP(buf[:n], s.client); err != nil {
			u.stats.Error("client write: " + err.Error())
			u.closeSession(key, s, "client write failed")
			return
		}
		s.pktsOut.Add(1)
		s.lastSeen.Store(time.Now().UnixNano())
		u.stats.RecordPacket(stats.DirOut, int64(n), true)
	}
}

func (u *UDPListener) closeSession(key string, s *udpSession, reason string) {
	if s == nil || s.closed.Swap(true) {
		return
	}
	u.mu.Lock()
	if cur, ok := u.session[key]; ok && cur == s {
		delete(u.session, key)
	}
	u.mu.Unlock()
	_ = s.upstream.Close()
	u.active.Add(-1)
	u.stats.ConnClosed()
	u.log.Debugf("udp", "session %s closed (%s)", key, reason)
}

// reapLoop closes sessions whose client went silent even when the upstream
// socket never produced a read timeout (for example a broken pipe).
func (u *UDPListener) reapLoop() {
	defer u.wg.Done()
	interval := u.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-u.done:
			return
		case <-t.C:
			now := time.Now()
			u.mu.Lock()
			type victim struct {
				key string
				s   *udpSession
			}
			var dead []victim
			for k, s := range u.session {
				if now.Sub(time.Unix(0, s.lastSeen.Load())) >= u.ttl {
					dead = append(dead, victim{k, s})
				}
			}
			u.mu.Unlock()
			for _, v := range dead {
				u.closeSession(v.key, v.s, "idle timeout")
			}
		}
	}
}

// Stop closes the listener and all sessions.
func (u *UDPListener) Stop() {
	u.closeO.Do(func() {
		close(u.done)
		if u.conn != nil {
			_ = u.conn.Close()
		}
		u.mu.Lock()
		for _, s := range u.session {
			s.closed.Store(true)
			_ = s.upstream.Close()
		}
		u.session = map[string]*udpSession{}
		u.mu.Unlock()
	})
	u.wg.Wait()
}

// Active reports the number of live client sessions.
func (u *UDPListener) Active() int64 { return u.active.Load() }

// Sessions reports how many clients are tracked right now.
func (u *UDPListener) Sessions() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.session)
}
