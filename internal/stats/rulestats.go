package stats

import "sync"

// Direction selects which side of a relay a byte belongs to.
type Direction int

const (
	// DirIn is client -> target traffic (received from the client).
	DirIn Direction = iota
	// DirOut is target -> client traffic (sent back to the client).
	DirOut
)

// RuleStats bundles counters with packet level accounting so both stream and
// datagram relays can share one type.
type RuleStats struct {
	*Counters
	mu sync.Mutex
}

// NewRuleStats creates counters for one rule.
func NewRuleStats() *RuleStats {
	return &RuleStats{Counters: NewCounters()}
}

// RecordPacket accounts for one read: its bytes and its packet count. Stream and
// datagram relays both use it, so the dashboard's packet columns are populated on
// every path.
func (r *RuleStats) RecordPacket(dir Direction, n int64, pkt bool) {
	inc := int64(0)
	if pkt {
		inc = 1
	}
	switch dir {
	case DirIn:
		r.AddRx(n, inc)
	default:
		r.AddTx(n, inc)
	}
}
