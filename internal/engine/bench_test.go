package engine

import (
	"encoding/binary"
	"net"
	"testing"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// The benchmarks in this file pin the cost of the raw relay's per-packet path.
// It is the hot path of the tool: with an "all protocols" rule every IP protocol
// except TCP and UDP goes through it, and a busy machine sees tens of thousands
// of packets per second there. `go test -bench . ./internal/engine/` is the way to
// check a change against the numbers quoted in the README.

func benchRawListener(b *testing.B) *RawListener {
	b.Helper()
	rule := &config.Rule{
		ID: "raw-bench", Kind: config.KindRaw, Protocol: "200",
		ListenHost: "172.16.0.32", TargetHost: "172.16.0.99", Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		b.Fatalf("validate: %v", err)
	}
	lg := logx.New(logx.Error, 50)
	lg.SetOutput(discardWriter{})
	rl, err := NewRawListener(rule, config.Settings{UDPSessionTTLSec: 5}, stats.NewRuleStats(), lg)
	if err != nil {
		b.Fatalf("NewRawListener: %v", err)
	}
	rl.sendIP = net.IPv4(172, 16, 0, 32)
	rl.listenIPs = []net.IP{net.IPv4(172, 16, 0, 32)}
	rl.target = net.IPv4(172, 16, 0, 99)
	// The recorder copies every packet and would dominate the measurement, so the
	// benchmarks use a sender that does not.
	rl.send = &nullSender{}
	return rl
}

// benchPacket builds a captured packet of the given payload size.
func benchPacket(payloadLen int) []byte {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:], 1)
	pkt[8] = 64
	pkt[9] = 200
	copy(pkt[12:16], net.IPv4(172, 16, 0, 40).To4())
	copy(pkt[16:20], net.IPv4(172, 16, 0, 32).To4())
	binary.BigEndian.PutUint16(pkt[10:], netutil.Checksum(pkt[:20]))
	copy(pkt[20:], payload)
	return pkt
}

// BenchmarkRawHandlePacket is the whole per-packet path with an established
// session: parse, match, rewrite, send.
func BenchmarkRawHandlePacket(b *testing.B) {
	rl := benchRawListener(b)
	pkt := benchPacket(512)
	rl.handlePacket(pkt)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.handlePacket(pkt)
	}
}

// BenchmarkRawHandlePacketSmall is the same for 40 byte datagrams, where the
// per-packet overhead rather than the payload dominates.
func BenchmarkRawHandlePacketSmall(b *testing.B) {
	rl := benchRawListener(b)
	pkt := benchPacket(20)
	rl.handlePacket(pkt)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.handlePacket(pkt)
	}
}

// BenchmarkRawHandlePacketFullTable repeats the measurement with the session
// table at its default cap, so a per-packet table scan would show up.
func BenchmarkRawHandlePacketFullTable(b *testing.B) {
	rl := benchRawListener(b)
	pkt := benchPacket(512)
	rl.handlePacket(pkt)
	rl.mu.Lock()
	for i := len(rl.byClient); i < rawSessionMaxCeiling; i++ {
		s := &rawSession{
			key: clientKey{
				ip:    [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)},
				port:  uint16(i),
				ident: uint16(i >> 3),
			},
			clientIP:   net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
			proxyPort:  uint16(40000 + i%20000),
			targetIP:   net.IPv4(172, 16, 0, 99),
			viaIP:      net.IPv4(172, 16, 0, 32),
			targetPort: 9000,
		}
		rl.byClient[s.key] = s
	}
	rl.mu.Unlock()
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.handlePacket(pkt)
	}
}

func BenchmarkParseHeader(b *testing.B) {
	pkt := benchPacket(512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := netutil.ParseHeader(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRewriteToTarget(b *testing.B) {
	rl := benchRawListener(b)
	pkt := benchPacket(512)
	rl.handlePacket(pkt)
	h, _ := netutil.ParseHeader(pkt)
	pl := pkt[h.IHL:]
	ident, hasIdent := rl.flowOf(pl)
	sess, _ := rl.sessionFor(h, ident, hasIdent)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rl.rewriteToTarget(pkt, h, pl, sess); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOwnEgressCheck(b *testing.B) {
	rl := benchRawListener(b)
	pkt := benchPacket(512)
	h, _ := netutil.ParseHeader(pkt)
	pl := pkt[h.IHL:]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if rl.isOwnEgress(h, pl) {
			b.Fatal("unexpected echo")
		}
	}
}
