package engine

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/stats"
)

// transparentMinConns is the floor for the TCP part of a multi-listener rule, and
// transparentDefaultConns is what the TCP part gets when the rule sets no
// maxConns at all.
//
// The parts of an "all protocols" rule share its session budget, which leaves the
// TCP half with the budget divided by ~252 (16 connections for the default
// budget, 10 for a 2520 one). That is far below what a single forwarded port
// serves: measured against a real target, a 30-connection burst had half of its
// connections accepted and then dropped, because the rest was refused. A TCP
// session cannot be created by a spoofed packet the way a raw or UDP one can, so
// this floor does not weaken the flood protection the budget exists for; the rule
// as a whole still stays in the low thousands of sessions.
const (
	transparentMinConns     = 512
	transparentDefaultConns = 4096
)

// MultiListener runs one rule on several listeners at once. It is what lets a
// single rule carry "all" protocols: TCP through the kernel stack, UDP as
// datagrams, and one raw socket per remaining protocol number. Every part
// shares the rule's counters, so the dashboard shows one line per rule while the
// traffic is split internally.
type MultiListener struct {
	rule  *config.Rule
	st    *stats.RuleStats
	log   *logx.Logger
	parts []runner
	names []string

	// poller is the shared WSAPoll set every raw part registers its capture
	// socket with. Held here so it is stopped exactly once, after the parts.
	poller *rawPollSet

	done   chan struct{}
	closed sync.Once
	wg     sync.WaitGroup

	active atomic.Int64
	err    error
}

// NewMultiListener builds the listener set for an "all protocol" rule.
func NewMultiListener(rule *config.Rule, set config.Settings, st *stats.RuleStats, log *logx.Logger) (*MultiListener, error) {
	protoNumbers, err := rule.ProtocolList()
	if err != nil {
		return nil, err
	}
	m := &MultiListener{rule: rule, st: st, log: log, done: make(chan struct{})}

	// Every part gets an equal share of the rule's session budget. Without this an
	// "all" rule would inherit one full budget per protocol number (250 of them),
	// which is far more than the rule's maxConns promises.
	partCount := len(protoNumbers) + 2 // + TCP + UDP
	share := config.AllProtocolSessionShare(rule, partCount)

	// TCP: the kernel stack has to terminate it (Windows refuses raw TCP), which
	// is also why Validate requires a target port for an "all" rule.
	//
	// The TCP half does not take the equal share: a raw or UDP session can be
	// created from a spoofed packet, so their caps are a real protection, while a
	// TCP connection can only exist because a client completed a handshake. An
	// explicit maxConns still applies, but not below what one busy port needs.
	tcpRule := *rule
	tcpRule.Kind = config.KindRaw
	tcpRule.Protocol = "tcp"
	tcpRule.RawTransport = config.RawTransparent
	switch {
	case tcpRule.MaxConns == 0:
		tcpRule.MaxConns = transparentDefaultConns
	case tcpRule.MaxConns < transparentMinConns:
		tcpRule.MaxConns = transparentMinConns
	}
	m.parts = append(m.parts, NewTransparentTCPListener(&tcpRule, set, st, log))
	m.names = append(m.names, "tcp")

	// UDP: the ordinary datagram relay, which preserves boundaries and sessions.
	udpRule := *rule
	udpRule.Kind = config.KindUDP
	udpRule.Protocol = ""
	udpRule.RawTransport = ""
	udpRule.MaxConns = share
	m.parts = append(m.parts, NewUDPListener(&udpRule, set, st, log))
	m.names = append(m.names, "udp")

	// Everything else: one raw socket per protocol number, so an unrelated
	// protocol number arriving on the wire cannot disturb the others. The sockets
	// share a single WSAPoll call (see rawPollSet): parking 250 sockets in 250
	// separate calls costs ~6% of a core while idle, one call covering all of them
	// costs 0.26%.
	poll := newRawPollSet()
	m.poller = poll
	for _, num := range protoNumbers {
		rawRule := *rule
		rawRule.Kind = config.KindRaw
		rawRule.Protocol = fmt.Sprint(num)
		rawRule.RawTransport = config.RawOwn
		rawRule.MaxConns = share
		rl, err := NewRawListener(&rawRule, set, st, log)
		if err != nil {
			return nil, fmt.Errorf("协议 %d：%w", num, err)
		}
		rl.poller = poll
		m.parts = append(m.parts, rl)
		m.names = append(m.names, config.ProtocolName(num))
	}
	return m, nil
}

// Start starts every part, skipping the ones this host refuses (some protocol
// numbers and some drivers reject raw capture) so a single unsupported protocol
// cannot take the whole rule down. It fails only when nothing started.
func (m *MultiListener) Start() error {
	started := 0
	var failed []string
	for i, part := range m.parts {
		if err := part.Start(); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", m.names[i], err))
			m.log.Warnf("engine", "全协议规则 %q 的 %s 部分启动失败：%v", m.rule.Name, m.names[i], err)
			continue
		}
		started++
	}
	if started == 0 {
		if len(failed) > 0 {
			return fmt.Errorf("全协议规则没有任何监听器启动成功（%s）", strings.Join(failed, "; "))
		}
		return fmt.Errorf("全协议规则没有可用的监听器")
	}
	if len(failed) > 0 {
		m.err = fmt.Errorf("%d 个协议未能启动：%s", len(failed), strings.Join(failed, "; "))
	}
	m.log.Infof("engine", "全协议规则 %q 已启动 %d 个监听器（TCP 透明转发 + UDP + 原始套接字）", m.rule.Name, started)

	m.wg.Add(1)
	go m.activeLoop()
	return nil
}

// activeLoop keeps the rule's session gauge in step with its parts.
func (m *MultiListener) activeLoop() {
	defer m.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			var total int64
			for _, part := range m.parts {
				total += part.Active()
			}
			m.active.Store(total)
		}
	}
}

// Stop shuts every part down. Parts stop in parallel: each raw listener waits
// for its capture poll to notice the shutdown, and doing 250 of those in
// sequence would take tens of seconds.
func (m *MultiListener) Stop() {
	m.closed.Do(func() { close(m.done) })
	var wg sync.WaitGroup
	for _, part := range m.parts {
		wg.Add(1)
		go func(p runner) {
			defer wg.Done()
			p.Stop()
		}(part)
	}
	wg.Wait()
	if m.poller != nil {
		m.poller.stop()
	}
	m.wg.Wait()
}

// Active reports the summed live sessions of all parts.
func (m *MultiListener) Active() int64 { return m.active.Load() }

// Err reports the partial startup failure, if any part refused to start.
func (m *MultiListener) Err() error { return m.err }
