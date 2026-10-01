package netutil

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestProbeChecksumFuzz feeds random-length buffers to the checksum helpers to be
// sure none of them panics on short or odd-sized input, which is reachable from
// the network.
func TestChecksumHelpersHandleShortBuffers(t *testing.T) {
	protos := []uint8{ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6, ProtoSCTP, ProtoDCCP, ProtoUDPLite, ProtoGRE, 200}
	for size := 0; size < 48; size++ {
		buf := make([]byte, size)
		for i := range buf {
			buf[i] = byte(i * 7)
		}
		for _, proto := range protos {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("PatchTransportChecksum(proto=%d, len=%d) panicked: %v", proto, size, r)
					}
				}()
				var d Delta
				d.ReplaceAddr(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8))
				d.Replace(0x1234, 0x5678)
				err := PatchTransportChecksum(proto, buf, &d)
				if err != nil && err != ErrShortSegment && err != ErrNoChecksum {
					t.Fatalf("unexpected error for proto=%d len=%d: %v", proto, size, err)
				}
			}()
		}
		// The header parsers must also handle every size without panicking.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseHeader/ParseFlow panicked at len=%d: %v", size, r)
				}
			}()
			_, _ = ParseHeader(buf)
			_, _ = ParseFlow(ProtoTCP, buf)
			_, _ = ParseFlow(ProtoICMP, buf)
			_, _ = ParseFlow(ProtoGRE, buf)
			_, _ = ParseFlow(ProtoESP, buf)
			_, _, _ = Ports(ProtoUDP, buf)
			_, _, _ = PortsIn(buf)
			_, _ = Checksum(buf), SumWords(0, buf)
			_ = binary.BigEndian.Uint16
		}()
	}
}
