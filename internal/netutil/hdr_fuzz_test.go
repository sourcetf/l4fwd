package netutil

import (
	"math/rand"
	"net"
	"testing"
)

// TestHeaderParserSurvivesRandomInput throws structurally random "IP packets" at
// the parser. Nothing that arrives on a raw socket may panic the relay.
func TestHeaderParserSurvivesRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(20260930))
	for i := 0; i < 20000; i++ {
		n := rng.Intn(80)
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = byte(rng.Intn(256))
		}
		// Bias the version nibble to IPv4 half of the time so the parser gets past
		// the first check and has to handle the rest.
		if n > 0 && i%2 == 0 {
			buf[0] = 0x40 | byte(rng.Intn(16))
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iteration %d panicked on % x: %v", i, buf, r)
				}
			}()
			h, err := ParseHeader(buf)
			if err == nil && h != nil {
				_ = h.Encode()
				_ = h.IsFragment()
				_ = h.HeaderLen()
				_, _ = RewriteHeader(buf, h.Src, h.Dst, 0, 0)
			}
			_, _ = ParseFlow(ProtoTCP, buf)
			_, _ = ParseFlow(ProtoUDP, buf)
			_, _ = ParseFlow(ProtoICMP, buf)
			_, _ = ParseFlow(ProtoICMPv6, buf)
			_, _ = ParseFlow(ProtoGRE, buf)
			_, _ = ParseFlow(ProtoESP, buf)
			_, _ = ParseFlow(200, buf)
			var d Delta
			src, dst := net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8)
			if h != nil {
				if h.Src != nil {
					src = h.Src
				}
				if h.Dst != nil {
					dst = h.Dst
				}
			}
			d.ReplaceAddr(src, dst)
			_ = PatchTransportChecksum(ProtoTCP, buf, &d)
			_ = PatchTransportChecksum(ProtoUDP, buf, &d)
			_ = PatchTransportChecksum(ProtoICMP, buf, &d)
			_ = PatchTransportChecksum(ProtoSCTP, buf, &d)
			_ = RecomputeSCTP(buf)
		}()
	}
}
