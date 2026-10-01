package stats

import "sync"

// Sampler periodically computes per-rule byte and packet rates from raw counters.
type Sampler struct {
	mu    sync.Mutex
	items map[string]*sampleItem
	stop  chan struct{}
	once  sync.Once
}

type sampleItem struct {
	c          *Counters
	lastRx     int64
	lastTx     int64
	lastRxPkts int64
	lastTxPkts int64
}

// NewSampler returns an idle sampler.
func NewSampler() *Sampler {
	return &Sampler{items: map[string]*sampleItem{}, stop: make(chan struct{})}
}

// Track starts sampling the given counters under a key.
func (s *Sampler) Track(key string, c *Counters) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rx, tx, rxPkts, txPkts := c.Raw()
	s.items[key] = &sampleItem{
		c:          c,
		lastRx:     rx,
		lastTx:     tx,
		lastRxPkts: rxPkts,
		lastTxPkts: txPkts,
	}
}

// Untrack stops sampling a key.
func (s *Sampler) Untrack(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

// Tick computes rates for all tracked counters; call once per interval. Bytes and
// packets are sampled together so the dashboard can show how busy a rule is even
// when its datagrams are small.
func (s *Sampler) Tick(intervalSec float64) {
	if intervalSec <= 0 {
		intervalSec = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range s.items {
		rx, tx, rxPkts, txPkts := it.c.Raw()
		in := rate(rx-it.lastRx, intervalSec)
		out := rate(tx-it.lastTx, intervalSec)
		pktIn := rate(rxPkts-it.lastRxPkts, intervalSec)
		pktOut := rate(txPkts-it.lastTxPkts, intervalSec)
		it.c.SetSpeed(in, out, pktIn, pktOut)
		it.lastRx, it.lastTx = rx, tx
		it.lastRxPkts, it.lastTxPkts = rxPkts, txPkts
	}
}

// rate converts a counter delta into a per-second value, guarding against a
// counter that went backwards (a rule restart reusing the same key).
func rate(delta int64, intervalSec float64) int64 {
	if delta <= 0 {
		return 0
	}
	return int64(float64(delta) / intervalSec)
}

// Stop terminates the sampler loop started by Run.
func (s *Sampler) Stop() {
	s.once.Do(func() { close(s.stop) })
}

// Done returns a channel closed when the sampler stops.
func (s *Sampler) Done() <-chan struct{} { return s.stop }
