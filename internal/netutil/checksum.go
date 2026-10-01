package netutil

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
)

// Protocol numbers used when fixing transport checksums.
const (
	ProtoICMP    = 1
	ProtoIGMP    = 2
	ProtoIPv4    = 4
	ProtoTCP     = 6
	ProtoUDP     = 17
	ProtoDCCP    = 33
	ProtoIPv6    = 41
	ProtoGRE     = 47
	ProtoESP     = 50
	ProtoAH      = 51
	ProtoICMPv6  = 58
	ProtoSCTP    = 132
	ProtoUDPLite = 136
)

// ErrNoChecksum means the protocol carries no checksum that depends on the IP
// addresses, so rewriting addresses needs no fixup.
var ErrNoChecksum = errors.New("protocol has no address dependent checksum")

// ErrShortSegment means the datagram is too small to contain the header that
// would have to be patched.
var ErrShortSegment = errors.New("transport segment shorter than its header")

// fold16 folds a 32 bit one's complement accumulator into 16 bits.
func fold16(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

// FoldChecksum exposes the folding step for callers building their own sums.
func FoldChecksum(sum uint32) uint16 { return fold16(sum) }

// SumWords adds b to a 16 bit one's complement accumulator.
func SumWords(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// SumWordsAt adds the 16 bit words starting at off within b.
func SumWordsAt(sum uint32, b []byte, off, n int) uint32 {
	if off >= len(b) {
		return sum
	}
	end := off + n
	if end > len(b) {
		end = len(b)
	}
	return SumWords(sum, b[off:end])
}

// PseudoHeaderSum returns the address and protocol contribution of an IPv4
// pseudo header for a transport payload of the given length.
func PseudoHeaderSum(src, dst net.IP, proto uint8, length int) uint32 {
	s4, d4 := src.To4(), dst.To4()
	if s4 == nil || d4 == nil {
		return 0
	}
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(s4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d4[2:4]))
	sum += uint32(proto)
	sum += uint32(length)
	return sum
}

// Delta accumulates the effect of replacing 16 bit words inside a checksummed
// region. It implements the RFC 1624 incremental update, which works even for
// fragmented datagrams because the checksum field sits in the first fragment.
//
// The delta keeps addresses apart from everything else because the two kinds of
// transport checksum react differently to a rewrite:
//
//	pseudo header checksum (TCP/UDP/DCCP/UDP-Lite/ICMPv6): addresses + ports
//	ICMPv4:                                                ports and other
//	                                                       in-message fields
//	                                                       only, never addresses
//
// Keeping them separate lets PatchTransportChecksum pick the right subset
// without the caller having to know which protocol it is dealing with.
type Delta struct {
	// sum covers the pseudo header checksum: addresses, ports, identifiers.
	sum uint32
	// message covers only fields inside the transport message itself.
	message messageDelta
}

// messageDelta is the address-independent part of a delta.
type messageDelta struct {
	sum uint32
}

// Empty reports whether nothing inside the message changed.
func (m *messageDelta) Empty() bool { return m.sum == 0 }

// Apply applies the message-only delta to a stored checksum.
func (m *messageDelta) Apply(csum uint16) uint16 {
	return ^fold16(uint32(csum^0xffff) + m.sum)
}

// Replace records that the 16 bit word old is being replaced by new. The
// replacement is counted for both checksum families, so a caller that rewrites
// a port or an identifier inside the message does not have to say which kind of
// checksum the protocol uses.
func (d *Delta) Replace(old, new uint16) {
	effect := uint32(old^0xffff) + uint32(new)
	d.sum += effect
	d.message.sum += effect
}

// ReplaceMessage records a word replacement that only affects checksums covering
// the message itself (ports, ICMP identifiers, GRE keys).
func (d *Delta) ReplaceMessage(old, new uint16) {
	d.message.sum += uint32(old^0xffff) + uint32(new)
}

// ReplaceBytes records a word replacement at the given offset.
func (d *Delta) ReplaceBytes(oldB, newB []byte, off int) error {
	if len(oldB) < off+2 || len(newB) < off+2 {
		return ErrShortSegment
	}
	d.Replace(binary.BigEndian.Uint16(oldB[off:]), binary.BigEndian.Uint16(newB[off:]))
	return nil
}

// ReplaceAddr records an IPv4 address replacement. It only affects pseudo header
// checksums: the IP header is not part of any other transport checksum. Both
// arguments may be raw 4 byte addresses or 16 byte ones, and nothing is
// allocated either way.
func (d *Delta) ReplaceAddr(oldIP, newIP []byte) {
	o, n := ip4Bytes(oldIP), ip4Bytes(newIP)
	if len(o) != 4 || len(n) != 4 {
		return
	}
	d.sum += uint32(binary.BigEndian.Uint16(o[0:2])^0xffff) + uint32(binary.BigEndian.Uint16(n[0:2]))
	d.sum += uint32(binary.BigEndian.Uint16(o[2:4])^0xffff) + uint32(binary.BigEndian.Uint16(n[2:4]))
}

// Empty reports whether nothing was replaced.
func (d *Delta) Empty() bool { return d.sum == 0 && d.message.sum == 0 }

// MessageEmpty reports whether nothing inside the transport message changed.
func (d *Delta) MessageEmpty() bool { return d.message.sum == 0 }

// Apply applies the accumulated delta to a stored checksum.
func (d *Delta) Apply(csum uint16) uint16 {
	s := uint32(csum^0xffff) + d.sum
	return ^fold16(s)
}

// Recompute recomputes a pseudo header checksum from scratch; used when the
// whole payload is available (non fragmented traffic).
func Recompute(src, dst net.IP, proto uint8, payload []byte) uint16 {
	return ^fold16(PseudoHeaderSum(src, dst, proto, len(payload)) + SumWords(0, payload))
}

// ChecksumKind classifies how a protocol's checksum reacts to address changes.
type ChecksumKind int

const (
	// ChecksumNone: no checksum covering the addresses (GRE, ESP, AH, IPIP...).
	ChecksumNone ChecksumKind = iota
	// ChecksumPseudo: standard 16 bit pseudo header checksum (TCP, UDP, DCCP,
	// UDP-Lite, ICMPv6).
	ChecksumPseudo
	// ChecksumMessageOnly: 16 bit checksum without a pseudo header (ICMPv4).
	ChecksumMessageOnly
	// ChecksumCRC32c: SCTP style CRC32c, which cannot be updated incrementally
	// without the whole datagram.
	ChecksumCRC32c
)

// Kind returns the checksum classification of an IP protocol.
func Kind(proto uint8) ChecksumKind {
	switch proto {
	case ProtoTCP, ProtoUDP, ProtoDCCP, ProtoICMPv6, ProtoUDPLite:
		return ChecksumPseudo
	case ProtoICMP:
		return ChecksumMessageOnly
	case ProtoSCTP:
		return ChecksumCRC32c
	default:
		return ChecksumNone
	}
}

// transportChecksumOffset returns the byte offset of the checksum field inside
// the transport header, and whether the protocol has one.
func transportChecksumOffset(proto uint8) (int, bool) {
	switch proto {
	case ProtoTCP:
		return 16, true
	case ProtoUDP, ProtoUDPLite, ProtoDCCP:
		return 6, true
	case ProtoICMP, ProtoICMPv6:
		return 2, true
	case ProtoSCTP:
		return 8, true
	}
	return 0, false
}

// IsPortLike reports whether the transport header starts with a source and
// destination port, so rules may filter and translate by port.
func IsPortLike(proto uint8) bool {
	switch proto {
	case ProtoTCP, ProtoUDP, ProtoDCCP, ProtoUDPLite, ProtoSCTP:
		return true
	}
	return false
}

// FlowIdentity identifies a conversation inside a protocol that may be spread
// over several datagrams.
type FlowIdentity struct {
	SrcPort  uint16
	DstPort  uint16
	Ident    uint16
	Ident32  uint32
	HasPorts bool
	HasIdent bool
}

// Zero reports whether the identity carries no discriminator at all.
func (f FlowIdentity) Zero() bool { return !f.HasPorts && !f.HasIdent }

// ParseFlow extracts the flow identity of the transport payload, returning
// false when the protocol carries nothing usable for demultiplexing.
func ParseFlow(proto uint8, payload []byte) (FlowIdentity, bool) {
	switch proto {
	case ProtoTCP, ProtoUDP, ProtoDCCP, ProtoUDPLite, ProtoSCTP:
		if len(payload) < 4 {
			return FlowIdentity{}, false
		}
		return FlowIdentity{
			SrcPort:  binary.BigEndian.Uint16(payload[0:2]),
			DstPort:  binary.BigEndian.Uint16(payload[2:4]),
			HasPorts: true,
		}, true
	case ProtoICMP, ProtoICMPv6:
		if len(payload) < 8 {
			return FlowIdentity{}, false
		}
		switch payload[0] {
		case 0, 8, 128, 129: // echo reply / request, v4 and v6
			return FlowIdentity{Ident: binary.BigEndian.Uint16(payload[4:6]), HasIdent: true}, true
		}
		return FlowIdentity{}, false
	case ProtoGRE:
		if len(payload) < 4 {
			return FlowIdentity{}, false
		}
		flags := binary.BigEndian.Uint16(payload[0:2])
		if flags&0x2000 != 0 && len(payload) >= 8 { // key bit set
			return FlowIdentity{Ident: binary.BigEndian.Uint16(payload[4:6]), HasIdent: true}, true
		}
		return FlowIdentity{}, false
	case ProtoESP:
		if len(payload) < 8 {
			return FlowIdentity{}, false
		}
		return FlowIdentity{
			Ident:    binary.BigEndian.Uint16(payload[0:2]),
			Ident32:  binary.BigEndian.Uint32(payload[0:4]),
			HasIdent: true,
		}, true
	}
	return FlowIdentity{}, false
}

// Ports returns the source and destination port of the payload, if present.
func Ports(proto uint8, payload []byte) (src, dst uint16, ok bool) {
	if !IsPortLike(proto) || len(payload) < 4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(payload[0:2]), binary.BigEndian.Uint16(payload[2:4]), true
}

// PortsIn reads a port pair from the first four payload bytes without checking
// the protocol. It is used for bespoke protocols whose implementer put a port
// header inside the payload.
func PortsIn(payload []byte) (src, dst uint16, ok bool) {
	if len(payload) < 4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(payload[0:2]), binary.BigEndian.Uint16(payload[2:4]), true
}

// SetPortsIn writes a source/destination port pair into the first four payload
// bytes, leaving zero arguments untouched.
func SetPortsIn(payload []byte, src, dst uint16) {
	if len(payload) < 4 {
		return
	}
	if src != 0 {
		binary.BigEndian.PutUint16(payload[0:2], src)
	}
	if dst != 0 {
		binary.BigEndian.PutUint16(payload[2:4], dst)
	}
}

// PortOffset returns the byte offset of the source port inside the payload.
func PortOffset(proto uint8) (int, bool) {
	if !IsPortLike(proto) {
		return 0, false
	}
	return 0, true
}

// SetPorts rewrites the source or destination port of the payload in place.
func SetPorts(payload []byte, proto uint8, src, dst uint16) {
	if !IsPortLike(proto) || len(payload) < 4 {
		return
	}
	if src != 0 {
		binary.BigEndian.PutUint16(payload[0:2], src)
	}
	if dst != 0 {
		binary.BigEndian.PutUint16(payload[2:4], dst)
	}
}

// SetIdent rewrites the flow identifier (ICMP id, GRE key, ESP SPI in place.
func SetIdent(payload []byte, proto uint8, id uint16) {
	switch proto {
	case ProtoICMP, ProtoICMPv6:
		if len(payload) >= 6 {
			binary.BigEndian.PutUint16(payload[4:6], id)
		}
	case ProtoGRE:
		if len(payload) >= 6 {
			binary.BigEndian.PutUint16(payload[4:6], id)
		}
	case ProtoESP:
		// The SPI is integrity protected by the following HMAC, so rewriting
		// it breaks authentication; callers must opt in.
	}
}

// PatchTransportChecksum updates the transport checksum inside a forwarded
// packet using an incremental delta, which keeps fragmented datagrams valid
// because the checksum field only lives in the first fragment.
//
// The delta must describe the whole rewrite the relay applied to the transport
// bytes (addresses for pseudo header checksums, ports and identifiers for both
// kinds). Two special cases are handled here rather than by the caller:
//
//   - ICMPv4 does not cover the IP addresses, so a delta built only from an
//     address rewrite must leave its checksum alone. The delta carries an
//     address part and an optional message part for exactly this reason.
//   - A UDP checksum of zero means "not computed" (RFC 768) and must stay zero:
//     inventing a value would make a receiver that trusts the field drop the
//     datagram.
func PatchTransportChecksum(proto uint8, payload []byte, delta *Delta) error {
	off, ok := transportChecksumOffset(proto)
	if !ok || delta == nil || delta.Empty() {
		return nil
	}
	if len(payload) < off+2 {
		return ErrShortSegment
	}
	switch Kind(proto) {
	case ChecksumMessageOnly:
		// Only the fields inside the message affect this checksum; address
		// rewrites must not touch it.
		if delta.message.Empty() {
			return nil
		}
		old := binary.BigEndian.Uint16(payload[off:])
		binary.BigEndian.PutUint16(payload[off:], delta.message.Apply(old))
		return nil
	case ChecksumCRC32c:
		// A CRC32c is not a one's complement sum, so an incremental update would
		// silently corrupt it. Callers must recompute it over the whole datagram.
		return ErrNoChecksum
	case ChecksumPseudo:
		if proto == ProtoUDP || proto == ProtoUDPLite {
			if payload[off] == 0 && payload[off+1] == 0 {
				return nil // "not computed" stays not computed
			}
		}
	}
	old := binary.BigEndian.Uint16(payload[off:])
	binary.BigEndian.PutUint16(payload[off:], delta.Apply(old))
	return nil
}

// crc32cTable is the Castagnoli table used by SCTP.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// RecomputeSCTP fixes the CRC32c checksum of a complete, unfragmented SCTP
// packet in place.
func RecomputeSCTP(payload []byte) error {
	if len(payload) < 12 {
		return ErrShortSegment
	}
	payload[8], payload[9], payload[10], payload[11] = 0, 0, 0, 0
	binary.LittleEndian.PutUint32(payload[8:], crc32.Checksum(payload, crc32cTable))
	return nil
}
