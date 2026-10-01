package stats

import (
	"testing"
	"time"
)

// TestSamplerReportsBytesAndPackets checks both rates are sampled from the same
// tick: a rule carrying small datagrams must not look idle.
func TestSamplerReportsBytesAndPackets(t *testing.T) {
	s := NewSampler()
	c := NewCounters()
	s.Track("r", c)

	// One second worth of traffic: 1000 bytes in 10 packets each way.
	c.AddRx(1000, 10)
	c.AddTx(2000, 20)
	s.Tick(1)
	in, out := c.Speed()
	if in != 1000 || out != 2000 {
		t.Fatalf("byte rates = %d/%d, want 1000/2000", in, out)
	}
	pktIn, pktOut := c.PacketSpeed()
	if pktIn != 10 || pktOut != 20 {
		t.Fatalf("packet rates = %d/%d, want 10/20", pktIn, pktOut)
	}

	// Idle tick: everything falls back to zero.
	s.Tick(1)
	if in, out := c.Speed(); in != 0 || out != 0 {
		t.Fatalf("idle byte rates = %d/%d, want 0/0", in, out)
	}
	if pktIn, pktOut := c.PacketSpeed(); pktIn != 0 || pktOut != 0 {
		t.Fatalf("idle packet rates = %d/%d, want 0/0", pktIn, pktOut)
	}

	// A counter that appears to move backwards (a restarted rule reusing a key)
	// must not produce a negative rate.
	s2 := NewSampler()
	c2 := NewCounters()
	c2.AddRx(500, 5)
	s2.Track("r", c2)
	s2.Tick(1)
	c2.rxBytes.Store(0)
	c2.rxPkts.Store(0)
	s2.Tick(1)
	if in, _ := c2.Speed(); in < 0 {
		t.Fatalf("negative byte rate after a reset: %d", in)
	}
	if pktIn, _ := c2.PacketSpeed(); pktIn < 0 {
		t.Fatalf("negative packet rate after a reset: %d", pktIn)
	}
	_ = time.Second
}
