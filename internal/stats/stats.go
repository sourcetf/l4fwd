// Package stats implements lock-free-ish counters for rules and the process.
package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

// Counters is a set of counters plus connection gauges for one rule.
type Counters struct {
	rxBytes   atomic.Int64
	txBytes   atomic.Int64
	rxPkts    atomic.Int64
	txPkts    atomic.Int64
	conns     atomic.Int64 // total accepted connections/sessions
	errors    atomic.Int64
	txDrops   atomic.Int64
	active    atomic.Int64
	startedAt time.Time

	mu       sync.Mutex
	lastErr  string
	lastErrT time.Time
	speedIn  int64
	speedOut int64
	// Packet rates are sampled alongside the byte rates so the dashboard can show
	// how busy a rule is even when its datagrams are small.
	pktInBps  int64
	pktOutBps int64
}

// NewCounters returns counters started now.
func NewCounters() *Counters {
	return &Counters{startedAt: time.Now()}
}

// AddRx records received bytes/packets from the client side.
func (c *Counters) AddRx(bytes, pkts int64) {
	c.rxBytes.Add(bytes)
	if pkts > 0 {
		c.rxPkts.Add(pkts)
	}
}

// AddTx records bytes/packets sent towards the client side.
func (c *Counters) AddTx(bytes, pkts int64) {
	c.txBytes.Add(bytes)
	if pkts > 0 {
		c.txPkts.Add(pkts)
	}
}

// ConnAccepted increments the total connection counter.
func (c *Counters) ConnAccepted() { c.conns.Add(1) }

// ConnClosed decrements the active gauge.
func (c *Counters) ConnClosed() { c.active.Add(-1) }

// ConnOpened increments the active gauge.
func (c *Counters) ConnOpened() { c.active.Add(1) }

// Drop records a dropped packet (send failure, queue full, ...).
func (c *Counters) Drop(n int64) {
	if n <= 0 {
		n = 1
	}
	c.txDrops.Add(n)
}

// Error records an error with a short message.
func (c *Counters) Error(msg string) {
	c.errors.Add(1)
	c.mu.Lock()
	c.lastErr = msg
	c.lastErrT = time.Now()
	c.mu.Unlock()
}

// Snapshot is a JSON friendly view of the counters.
type Snapshot struct {
	RxBytes     int64  `json:"rxBytes"`
	TxBytes     int64  `json:"txBytes"`
	RxPkts      int64  `json:"rxPkts"`
	TxPkts      int64  `json:"txPkts"`
	Conns       int64  `json:"conns"`
	Active      int64  `json:"active"`
	Errors      int64  `json:"errors"`
	Drops       int64  `json:"drops"`
	UptimeSec   int64  `json:"uptimeSec"`
	LastError   string `json:"lastError,omitempty"`
	LastErrorAt string `json:"lastErrorAt,omitempty"`
	SpeedInBps  int64  `json:"speedInBps"`
	SpeedOutBps int64  `json:"speedOutBps"`
	PktInBps    int64  `json:"pktInBps"`
	PktOutBps   int64  `json:"pktOutBps"`
}

// Snapshot reads the current values.
func (c *Counters) Snapshot() Snapshot {
	c.mu.Lock()
	le, let := c.lastErr, c.lastErrT
	c.mu.Unlock()
	s := Snapshot{
		RxBytes:   c.rxBytes.Load(),
		TxBytes:   c.txBytes.Load(),
		RxPkts:    c.rxPkts.Load(),
		TxPkts:    c.txPkts.Load(),
		Conns:     c.conns.Load(),
		Active:    c.active.Load(),
		Errors:    c.errors.Load(),
		Drops:     c.txDrops.Load(),
		UptimeSec: int64(time.Since(c.startedAt).Seconds()),
		LastError: le,
	}
	if !let.IsZero() {
		s.LastErrorAt = let.Format(time.RFC3339)
	}
	return s
}

// Raw returns the raw counters the speed sampler diffs between ticks.
func (c *Counters) Raw() (rx, tx, rxPkts, txPkts int64) {
	return c.rxBytes.Load(), c.txBytes.Load(), c.rxPkts.Load(), c.txPkts.Load()
}

// SetSpeed stores a sampled rate, in bytes and in packets per second.
func (c *Counters) SetSpeed(in, out, pktIn, pktOut int64) {
	c.mu.Lock()
	c.speedIn, c.speedOut = in, out
	c.pktInBps, c.pktOutBps = pktIn, pktOut
	c.mu.Unlock()
}

// Speed returns the last sampled byte rates.
func (c *Counters) Speed() (in, out int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.speedIn, c.speedOut
}

// PacketSpeed returns the last sampled packet rates.
func (c *Counters) PacketSpeed() (in, out int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pktInBps, c.pktOutBps
}
