package engine

import (
	"sync"
	"time"

	"l4fwd/internal/netutil"
)

// rawPollSet waits on the capture sockets of one rule with a single WSAPoll call.
//
// An "all protocols" rule opens one raw socket per IP protocol (~250 of them). If
// every socket parks in its own WSAPoll call, the process pays ~250 syscalls plus
// 250 goroutine wakeups every poll interval: measured on this machine, 6% of a
// core while doing nothing at all. One WSAPoll call covering all of the sockets
// costs the same as one of those calls, which measured 0.26% — a 23x idle
// reduction for the rule shape the tool is usually run with.
//
// Each socket keeps its own capture goroutine, which is what preserves packet
// throughput: the poller only tells a listener "your socket has data", and the
// listener drains it on its own goroutine, so several protocols are still
// processed in parallel.
type rawPollSet struct {
	mu      sync.Mutex
	entries []*pollEntry

	done chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

// pollEntry is one socket in the set. detached is set (under the set's lock) when
// the owner stops using the socket, so a poll result that arrives after that is
// ignored instead of waking a goroutine that has already gone away.
type pollEntry struct {
	fd       uintptr
	wake     chan struct{} // buffered 1: a wakeup that is already pending is not lost
	detached bool
}

// pollSetInterval is how long one WSAPoll call parks. Closing a socket does not
// interrupt a parked WSAPoll on Windows (verified), so the poller relies on this
// timeout to notice that it has been shut down.
const pollSetInterval pollInterval = pollInterval(200 * time.Millisecond)

func newRawPollSet() *rawPollSet {
	p := &rawPollSet{done: make(chan struct{})}
	p.wg.Add(1)
	go p.loop()
	return p
}

// register adds a socket and returns the channel its listener waits on, plus a
// function that removes it again. The removal marks the entry detached and takes
// it out of the set, so a wakeup that is already in flight is dropped rather than
// delivered to a listener that has stopped.
func (p *rawPollSet) register(fd uintptr) (<-chan struct{}, func()) {
	entry := &pollEntry{fd: fd, wake: make(chan struct{}, 1)}
	p.mu.Lock()
	p.entries = append(p.entries, entry)
	p.mu.Unlock()

	remove := func() {
		p.mu.Lock()
		entry.detached = true
		for i, e := range p.entries {
			if e == entry {
				p.entries = append(p.entries[:i], p.entries[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
	}
	return entry.wake, remove
}

// stop shuts the poller down and waits for its goroutine.
func (p *rawPollSet) stop() {
	p.once.Do(func() { close(p.done) })
	p.wg.Wait()
}

// count reports how many sockets are being waited on.
func (p *rawPollSet) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

func (p *rawPollSet) loop() {
	defer p.wg.Done()
	socks := make([]netutil.PollOne, 0, 256)
	for {
		p.mu.Lock()
		entries := make([]*pollEntry, len(p.entries))
		copy(entries, p.entries)
		p.mu.Unlock()

		if len(entries) == 0 {
			select {
			case <-p.done:
				return
			case <-time.After(time.Duration(pollSetInterval)):
			}
			continue
		}

		socks = socks[:0]
		for _, e := range entries {
			socks = append(socks, netutil.PollOne{FD: e.fd})
		}
		ready, err := netutil.PollReady(socks, pollSetInterval.ms())
		if err != nil {
			select {
			case <-p.done:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		select {
		case <-p.done:
			return
		default:
		}
		for _, i := range ready {
			if i < 0 || i >= len(entries) {
				continue
			}
			if entries[i].detached {
				continue
			}
			// A pending wakeup is not worth queueing twice: the listener drains
			// the socket until it is empty, so a coalesced wakeup cannot lose a
			// packet.
			select {
			case entries[i].wake <- struct{}{}:
			default:
			}
		}
	}
}

// pollInterval is a duration in milliseconds, named so call sites read clearly.
type pollInterval time.Duration

// ms renders the interval in whole milliseconds, at least 1.
func (d pollInterval) ms() int {
	v := int(time.Duration(d) / time.Millisecond)
	if v < 1 {
		v = 1
	}
	return v
}
