// Package netutil holds IP/packet helpers shared by the relay engines:
// address parsing, interface discovery and IPv4 header (de)serialisation.
package netutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrShortHeader = errors.New("ip: packet shorter than header")
	ErrNotIPv4     = errors.New("ip: packet is not IPv4")
)

// ParsePort accepts a number or a service name ("8080", "http").
func ParsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty port")
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n > 65535 {
			return 0, fmt.Errorf("port %d out of range 0-65535", n)
		}
		return n, nil
	}
	if p, err := net.LookupPort("tcp", s); err == nil {
		return p, nil
	}
	return 0, fmt.Errorf("invalid port %q", s)
}

// ParseListen accepts ":8080", "8080", "0.0.0.0:8080" or "[::]:8080" and
// returns the host part (may be empty meaning all interfaces) and the port.
func ParseListen(spec string) (string, int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", 0, errors.New("empty listen spec")
	}
	host, portPart := "", spec
	if i := strings.LastIndex(spec, ":"); i >= 0 {
		host = spec[:i]
		portPart = spec[i+1:]
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	port, err := ParsePort(portPart)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// NormalizeHost strips brackets from an IPv6 literal and returns the host.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host
}

// IsWildcardHost reports whether the host means "all interfaces".
func IsWildcardHost(host string) bool {
	switch NormalizeHost(host) {
	case "", "0.0.0.0", "::", "*", "any":
		return true
	}
	return false
}

var (
	localIPOnce sync.Once
	localIPs    []net.IP
)

// LocalIPv4s returns every usable IPv4 address of this machine.
func LocalIPv4s() []net.IP {
	refresh := func() {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		seen := map[string]bool{}
		out := make([]net.IP, 0, 4)
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			if seen[ip4.String()] {
				continue
			}
			seen[ip4.String()] = true
			out = append(out, ip4)
		}
		localIPs = out
	}
	localIPOnce.Do(func() {})
	// Always refresh: adapters can change while the tool runs.
	refresh()
	return localIPs
}

// IsLocalIPv4 reports whether ip belongs to this machine (loopback included).
func IsLocalIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsLoopback() {
		return true
	}
	for _, l := range LocalIPv4s() {
		if l.Equal(ip4) {
			return true
		}
	}
	return false
}

// ResolveIPv4 resolves host to a single IPv4 address (a literal is used as is).
func ResolveIPv4(host string) (net.IP, error) {
	host = NormalizeHost(host)
	if host == "" {
		return nil, errors.New("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("not an IPv4 address: %s", host)
		}
		return ip4, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address for %s", host)
}

// Header is a decoded IPv4 header (options are carried verbatim).
type Header struct {
	IHL      int    // header length in bytes
	TOS      uint8  // type of service / DSCP
	TotalLen int    // total packet length as declared in the header
	ID       uint16 // identification
	Flags    uint8  // 3 bits: reserved, DF, MF
	FragOff  uint16 // fragment offset in 8 byte units
	TTL      uint8
	Proto    uint8
	Checksum uint16
	// Src and Dst are 4 byte addresses. They are []byte rather than net.IP so a
	// decode costs nothing: net.IPv4 allocates, and this runs for every captured
	// packet. Use Text or net.IP(h.Src) where a net.IP is wanted; the helpers in
	// this package (EqualIP, ReplaceAddr, ...) accept both shapes.
	Src     []byte
	Dst     []byte
	Options []byte // raw option bytes, may be empty
}

// Flags bit values as they appear in the low 3 bits of the flags field.
const (
	FlagMF uint8 = 0x1 // more fragments
	FlagDF uint8 = 0x2 // do not fragment
)

// ParseHeader decodes an IPv4 header from b into a fresh Header.
func ParseHeader(b []byte) (*Header, error) {
	h := &Header{}
	if err := h.Decode(b); err != nil {
		return nil, err
	}
	return h, nil
}

// Decode fills h from b, reusing h's storage. It is the allocation free form used
// on the packet path, where one Header per listener is enough: the decode is only
// valid until the next call.
func (h *Header) Decode(b []byte) error {
	if len(b) < 20 {
		return ErrShortHeader
	}
	if b[0]>>4 != 4 {
		return ErrNotIPv4
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return fmt.Errorf("ip: bad IHL %d", ihl)
	}
	h.IHL = ihl
	h.TOS = b[1]
	h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	h.ID = binary.BigEndian.Uint16(b[4:6])
	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	h.FragOff = flagsFrag & 0x1fff
	h.Flags = uint8(flagsFrag >> 13)
	h.TTL = b[8]
	h.Proto = b[9]
	h.Checksum = binary.BigEndian.Uint16(b[10:12])
	// Addresses alias the packet bytes; they are only read, and the packet lives
	// until the relay is done with it.
	h.Src = b[12:16]
	h.Dst = b[16:20]
	if ihl > 20 {
		h.Options = append(h.Options[:0], b[20:ihl]...)
	} else {
		h.Options = nil
	}
	return nil
}

// HeaderLen returns the header length that would be used for h (padded to 4).
func (h *Header) HeaderLen() int {
	l := 20 + len(h.Options)
	if r := l % 4; r != 0 {
		l += 4 - r
	}
	return l
}

// Encode writes the header into a fresh slice, recomputing the checksum.
func (h *Header) Encode() []byte {
	hl := h.HeaderLen()
	b := make([]byte, hl)
	b[0] = 0x40 | byte(hl/4)
	b[1] = h.TOS
	binary.BigEndian.PutUint16(b[2:], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[4:], h.ID)
	binary.BigEndian.PutUint16(b[6:], (uint16(h.Flags)<<13)|(h.FragOff&0x1fff))
	b[8] = h.TTL
	b[9] = h.Proto
	copy(b[12:16], h.Src4())
	copy(b[16:20], h.Dst4())
	copy(b[20:], h.Options)
	binary.BigEndian.PutUint16(b[10:12], Checksum(b[:hl]))
	return b
}

// IsFragment reports whether the packet (or any fragment) is part of a
// fragmented datagram. Non-initial fragments carry no transport header.
func (h *Header) IsFragment() bool { return h.FragOff != 0 || h.Flags&FlagMF != 0 }

// Src4 returns the source address as the four bytes of an IPv4 address.
func (h *Header) Src4() []byte { return ip4Bytes(h.Src) }

// Dst4 returns the destination address as the four bytes of an IPv4 address.
func (h *Header) Dst4() []byte { return ip4Bytes(h.Dst) }

// SrcIP and DstIP expose the addresses as net.IP for callers that want the
// net package's helpers. They allocate, so the packet path uses Src4/Dst4.
func (h *Header) SrcIP() net.IP { return net.IP(h.Src4()) }
func (h *Header) DstIP() net.IP { return net.IP(h.Dst4()) }

// ip4Bytes normalises an IP address to its four byte form without allocating for
// the common case of a 4 byte address.
func ip4Bytes(ip []byte) []byte {
	if len(ip) == 4 {
		return ip
	}
	if len(ip) == 16 {
		return ip[12:16]
	}
	return ip
}

// Checksum computes the 16 bit one's complement checksum of b.
func Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// RewriteHeader produces a new copy of the IP packet pkt with source and
// destination replaced, updating the header checksum. Options are preserved.
// Payload bytes are copied unchanged.
func RewriteHeader(pkt []byte, src, dst net.IP, proto uint8, ttl uint8) ([]byte, error) {
	h, err := ParseHeader(pkt)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(pkt))
	copy(out, pkt)
	out[0] = pkt[0] // version/IHL unchanged
	if proto != 0 {
		out[9] = proto
	}
	if ttl != 0 {
		out[8] = ttl
	}
	copy(out[12:16], src.To4())
	copy(out[16:20], dst.To4())
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], Checksum(out[:h.IHL]))
	return out, nil
}

// EqualIP compares two addresses, treating IPv4 and IPv4-in-IPv6 as equal.
func EqualIP(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 != nil && b4 != nil {
		return a4.Equal(b4)
	}
	return a.Equal(b)
}

// SameIP reports whether the address a — typically raw packet bytes — equals b,
// which may be a 4 byte or a 16 byte address. It never allocates, so it is what
// the packet path uses instead of net.IP.Equal.
func SameIP(a, b []byte) bool {
	a4 := ip4Bytes(a)
	b4 := ip4Bytes(b)
	return len(a4) == 4 && len(b4) == 4 &&
		a4[0] == b4[0] && a4[1] == b4[1] && a4[2] == b4[2] && a4[3] == b4[3]
}

// HashAddrs builds a compact map key for an address pair.
func HashAddrs(a, b net.IP) string {
	h := fnv.New64a()
	_, _ = h.Write(a.To16())
	_, _ = h.Write(b.To16())
	return strconv.FormatUint(h.Sum64(), 36)
}

// SleepCtx sleeps for d or until done is closed; it reports whether it slept fully.
func SleepCtx(d time.Duration, done <-chan struct{}) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}

// HostPort formats host and port for display, handling empty hosts and IPv6.
func HostPort(host string, port int) string {
	if host == "" {
		return ":" + strconv.Itoa(port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}
