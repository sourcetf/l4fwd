package netutil

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseHeaderRoundTrip(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	h := &Header{
		TOS:      0x10,
		TotalLen: 20 + len(payload),
		ID:       0x1234,
		Flags:    FlagDF,
		TTL:      64,
		Proto:    ProtoUDP,
		Src:      src,
		Dst:      dst,
	}
	hdr := h.Encode()
	if len(hdr) != 20 {
		t.Fatalf("header length = %d, want 20", len(hdr))
	}
	pkt := append(append([]byte(nil), hdr...), payload...)
	got, err := ParseHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got.TOS != h.TOS || got.ID != h.ID || got.TTL != h.TTL || got.Proto != h.Proto {
		t.Errorf("header mismatch: %+v vs %+v", got, h)
	}
	if !SameIP(got.Src, src) || !SameIP(got.Dst, dst) {
		t.Errorf("address mismatch: %v -> %v", got.Src, got.Dst)
	}
	if got.Flags != FlagDF {
		t.Errorf("flags = %d, want %d", got.Flags, FlagDF)
	}
	if Checksum(hdr) != 0 {
		t.Error("encoded header checksum does not verify")
	}
}

func TestParseHeaderRejectsGarbage(t *testing.T) {
	if _, err := ParseHeader([]byte{0x45, 0x00}); err == nil {
		t.Error("short buffer must fail")
	}
	bad := make([]byte, 24)
	bad[0] = 0x65 // version 6
	if _, err := ParseHeader(bad); err == nil {
		t.Error("IPv6 packet must be rejected")
	}
	bad2 := make([]byte, 24)
	bad2[0] = 0x44 // IHL 4 but version 4 -> 16 bytes, invalid
	if _, err := ParseHeader(bad2); err == nil {
		t.Error("bad IHL must be rejected")
	}
}

func TestChecksumKnownValue(t *testing.T) {
	hdr := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
		0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
	}
	const want = uint16(0xb1e6)
	if got := Checksum(hdr); got != want {
		t.Fatalf("Checksum = %#04x, want %#04x", got, want)
	}
	binary.BigEndian.PutUint16(hdr[10:12], want)
	if got := Checksum(hdr); got != 0 {
		t.Fatalf("checksum verification = %#04x, want 0", got)
	}
}

// TestDeltaMatchesFullRecompute is the correctness gate for the raw relay's
// incremental checksum repair: the delta path must agree with a full
// recomputation whenever the whole payload is available.
func TestDeltaMatchesFullRecompute(t *testing.T) {
	oldSrc := net.IPv4(192, 168, 1, 5)
	newSrc := net.IPv4(192, 168, 1, 250)
	dst := net.IPv4(10, 20, 30, 40)

	tcp := make([]byte, 20+13)
	tcp[0], tcp[1] = 0xc3, 0x50 // 50000
	tcp[2], tcp[3] = 0x01, 0xbb // 443
	tcp[12] = 0x50              // data offset 5
	for i := 20; i < len(tcp); i++ {
		tcp[i] = byte(i * 3)
	}
	base := Recompute(oldSrc, dst, ProtoTCP, tcp)
	binary.BigEndian.PutUint16(tcp[16:], base)

	var d Delta
	d.ReplaceAddr(oldSrc, newSrc)
	patched := base
	if err := PatchTransportChecksum(ProtoTCP, tcp, func() *Delta { return &d }()); err != nil {
		t.Fatalf("PatchTransportChecksum: %v", err)
	}
	patched = binary.BigEndian.Uint16(tcp[16:])

	wantPayload := append([]byte(nil), tcp...)
	wantPayload[16], wantPayload[17] = 0, 0
	want := Recompute(newSrc, dst, ProtoTCP, wantPayload)
	if patched != want {
		t.Fatalf("incremental checksum = %#04x, want %#04x", patched, want)
	}
}

// TestDeltaWithPortRewrite checks that rewriting a port together with an
// address still lands on the value a full recomputation would produce.
func TestDeltaWithPortRewrite(t *testing.T) {
	oldSrc := net.IPv4(172, 16, 0, 5)
	newSrc := net.IPv4(172, 16, 0, 99)
	dst := net.IPv4(172, 16, 0, 200)

	udp := make([]byte, 8+5)
	binary.BigEndian.PutUint16(udp[0:2], 34567)
	binary.BigEndian.PutUint16(udp[2:4], 5000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], []byte("hello"))

	base := Recompute(oldSrc, dst, ProtoUDP, udp)
	binary.BigEndian.PutUint16(udp[6:8], base)

	var d Delta
	d.ReplaceAddr(oldSrc, newSrc)
	d.Replace(34567, 40000)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	if err := PatchTransportChecksum(ProtoUDP, udp, &d); err != nil {
		t.Fatalf("PatchTransportChecksum: %v", err)
	}
	got := binary.BigEndian.Uint16(udp[6:8])

	ref := append([]byte(nil), udp...)
	ref[6], ref[7] = 0, 0
	want := Recompute(newSrc, dst, ProtoUDP, ref)
	if got != want {
		t.Fatalf("checksum = %#04x, want %#04x", got, want)
	}
}

func TestPatchTransportChecksumSkipsProtocolsWithoutOne(t *testing.T) {
	payload := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	orig := append([]byte(nil), payload...)
	var d Delta
	d.ReplaceAddr(net.IPv4(1, 1, 1, 1), net.IPv4(2, 2, 2, 2))
	if err := PatchTransportChecksum(ProtoGRE, payload, &d); err != nil {
		t.Fatalf("GRE must be a no-op, got %v", err)
	}
	if !bytes.Equal(payload, orig) {
		t.Fatal("payload modified for a protocol without checksum")
	}
}

func TestUDPZeroChecksumLeftAlone(t *testing.T) {
	// RFC 768: a zero UDP checksum means "not computed"; the relay must not
	// invent one when it rewrites addresses.
	if Kind(ProtoUDP) != ChecksumPseudo {
		t.Fatal("UDP should be classified as pseudo header checksum")
	}
}

func TestParseFlow(t *testing.T) {
	f, ok := ParseFlow(ProtoTCP, []byte{0x01, 0xbb, 0x00, 0x50})
	if !ok || !f.HasPorts || f.SrcPort != 443 || f.DstPort != 80 {
		t.Fatalf("tcp flow = %+v ok=%v", f, ok)
	}

	f, ok = ParseFlow(ProtoICMP, []byte{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01})
	if !ok || !f.HasIdent || f.Ident != 0x1234 {
		t.Fatalf("icmp echo flow = %+v ok=%v", f, ok)
	}

	if _, ok := ParseFlow(ProtoICMP, []byte{3, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("ICMP unreachable must not expose a flow identity")
	}
	if _, ok := ParseFlow(ProtoIPv4, []byte{0, 0, 0, 0}); ok {
		t.Fatal("IP-in-IP has no flow identity")
	}
	g := make([]byte, 8)
	binary.BigEndian.PutUint16(g[0:2], 0x3000) // key bit set
	binary.BigEndian.PutUint16(g[4:6], 0xbeef)
	f, ok = ParseFlow(ProtoGRE, g)
	if !ok || f.Ident != 0xbeef {
		t.Fatalf("GRE with key flow = %+v ok=%v", f, ok)
	}
	esp := make([]byte, 8)
	binary.BigEndian.PutUint32(esp[0:4], 0xdeadbeef)
	f, ok = ParseFlow(ProtoESP, esp)
	if !ok || f.Ident32 != 0xdeadbeef {
		t.Fatalf("ESP flow = %+v ok=%v", f, ok)
	}
}

func TestSetAndGetPorts(t *testing.T) {
	payload := make([]byte, 8)
	SetPorts(payload, ProtoTCP, 1111, 2222)
	src, dst, ok := Ports(ProtoTCP, payload)
	if !ok || src != 1111 || dst != 2222 {
		t.Fatalf("ports = %d/%d ok=%v", src, dst, ok)
	}
	// A zero argument leaves the corresponding field untouched.
	SetPorts(payload, ProtoTCP, 0, 3333)
	src, dst, _ = Ports(ProtoTCP, payload)
	if src != 1111 || dst != 3333 {
		t.Fatalf("ports after partial set = %d/%d", src, dst)
	}
	if _, _, ok := Ports(ProtoGRE, payload); ok {
		t.Fatal("GRE has no ports")
	}
}

func TestSCTPChecksum(t *testing.T) {
	payload := make([]byte, 16)
	copy(payload[0:2], []byte{0x12, 0x34})
	binary.BigEndian.PutUint16(payload[2:4], 0)
	binary.BigEndian.PutUint32(payload[4:8], 1)
	if err := RecomputeSCTP(payload); err != nil {
		t.Fatalf("RecomputeSCTP: %v", err)
	}
	// The CRC must be stable: recomputing over the finished packet yields the
	// same value.
	first := binary.LittleEndian.Uint32(payload[8:12])
	if err := RecomputeSCTP(payload); err != nil {
		t.Fatalf("RecomputeSCTP (second): %v", err)
	}
	if second := binary.LittleEndian.Uint32(payload[8:12]); second != first {
		t.Fatalf("CRC not stable: %#x vs %#x", first, second)
	}
	if first == 0 {
		t.Fatal("CRC must not be zero for this input")
	}
}

func TestHeaderWithOptions(t *testing.T) {
	src := net.IPv4(10, 1, 2, 3)
	dst := net.IPv4(10, 1, 2, 4)
	h := &Header{TotalLen: 28, TTL: 30, Proto: ProtoGRE, Src: src, Dst: dst, Options: []byte{0x94, 0x04, 0x00, 0x00}}
	enc := h.Encode()
	if len(enc) != 24 {
		t.Fatalf("encoded length = %d, want 24", len(enc))
	}
	back, err := ParseHeader(append(enc, make([]byte, 4)...))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if back.IHL != 24 || !bytes.Equal(back.Options, h.Options) {
		t.Fatalf("options lost: ihl=%d options=% x", back.IHL, back.Options)
	}
	if Checksum(enc[:back.IHL]) != 0 {
		t.Error("header with options has a bad checksum")
	}
}

func TestFragmentDetection(t *testing.T) {
	first := &Header{FragOff: 0, Flags: FlagMF}
	if !first.IsFragment() {
		t.Error("MF without offset is still a fragment")
	}
	second := &Header{FragOff: 185, Flags: 0}
	if !second.IsFragment() {
		t.Error("non-initial fragment must be reported as fragmented")
	}
	plain := &Header{FragOff: 0, Flags: FlagDF}
	if plain.IsFragment() {
		t.Error("DF without MF is not a fragment")
	}
}

func TestLocalIPv4sAndResolve(t *testing.T) {
	ips := LocalIPv4s()
	if len(ips) == 0 {
		t.Skip("machine reports no usable IPv4 address")
	}
	ip, err := ResolveIPv4(ips[0].String())
	if err != nil {
		t.Fatalf("ResolveIPv4(%s): %v", ips[0], err)
	}
	if !ip.Equal(ips[0]) {
		t.Fatalf("resolved %v, want %v", ip, ips[0])
	}
	if !IsLocalIPv4(ip) {
		t.Fatalf("%v should count as local", ip)
	}
	if IsLocalIPv4(net.IPv4(203, 0, 113, 5)) {
		t.Fatal("203.0.113.5 must not count as local")
	}
}

func TestIsLocalIPv4Loopback(t *testing.T) {
	if !IsLocalIPv4(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("loopback must be local")
	}
	if !IsLocalIPv4(net.IPv4(127, 9, 9, 9)) {
		t.Fatal("any 127.x address must be local")
	}
}

func TestSplitListenSpecs(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		port  int
		isErr bool
	}{
		{"8080", "", 8080, false},
		{":8080", "", 8080, false},
		{"0.0.0.0:8080", "0.0.0.0", 8080, false},
		{"127.0.0.1:80", "127.0.0.1", 80, false},
		{"", "", 0, true},
		{"abc", "", 0, true},
		{"70000", "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := ParseListen(tc.in)
		if tc.isErr {
			if err == nil {
				t.Errorf("ParseListen(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseListen(%q): %v", tc.in, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("ParseListen(%q) = (%q,%d), want (%q,%d)", tc.in, host, port, tc.host, tc.port)
		}
	}
}

func TestHostPortFormatting(t *testing.T) {
	if got := HostPort("", 80); got != ":80" {
		t.Errorf("HostPort(\"\",80) = %q", got)
	}
	if got := HostPort("1.2.3.4", 80); got != "1.2.3.4:80" {
		t.Errorf("HostPort ipv4 = %q", got)
	}
	if got := HostPort("::1", 80); got != "[::1]:80" {
		t.Errorf("HostPort ipv6 = %q", got)
	}
}

func TestRewriteHeader(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], 28)
	pkt[8] = 64
	pkt[9] = ProtoUDP
	copy(pkt[12:16], net.IPv4(1, 1, 1, 1).To4())
	copy(pkt[16:20], net.IPv4(2, 2, 2, 2).To4())
	binary.BigEndian.PutUint16(pkt[10:], Checksum(pkt[:20]))
	copy(pkt[20:], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	out, err := RewriteHeader(pkt, net.IPv4(3, 3, 3, 3), net.IPv4(4, 4, 4, 4), 0, 0)
	if err != nil {
		t.Fatalf("RewriteHeader: %v", err)
	}
	h, err := ParseHeader(out)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if !SameIP(h.Src, net.IPv4(3, 3, 3, 3).To4()) || !SameIP(h.Dst, net.IPv4(4, 4, 4, 4).To4()) {
		t.Fatalf("addresses not rewritten: %v -> %v", h.Src, h.Dst)
	}
	if Checksum(out[:20]) != 0 {
		t.Fatal("header checksum was not fixed after rewriting")
	}
	if !bytes.Equal(out[20:], pkt[20:]) {
		t.Fatal("payload changed during header rewrite")
	}
}

func TestKindClassification(t *testing.T) {
	cases := map[uint8]ChecksumKind{
		ProtoTCP:     ChecksumPseudo,
		ProtoUDP:     ChecksumPseudo,
		ProtoDCCP:    ChecksumPseudo,
		ProtoICMPv6:  ChecksumPseudo,
		ProtoUDPLite: ChecksumPseudo,
		ProtoICMP:    ChecksumMessageOnly,
		ProtoSCTP:    ChecksumCRC32c,
		ProtoGRE:     ChecksumNone,
		ProtoESP:     ChecksumNone,
		ProtoAH:      ChecksumNone,
		ProtoIPv4:    ChecksumNone,
		200:          ChecksumNone,
	}
	for proto, want := range cases {
		if got := Kind(proto); got != want {
			t.Errorf("Kind(%d) = %v, want %v", proto, got, want)
		}
	}
}

func TestNormalizeAndWildcardHost(t *testing.T) {
	if !IsWildcardHost("") || !IsWildcardHost("0.0.0.0") || !IsWildcardHost("*") || !IsWildcardHost("[::]") {
		t.Fatal("wildcard detection failed")
	}
	if IsWildcardHost("192.168.1.1") {
		t.Fatal("192.168.1.1 is not wildcard")
	}
	if got := NormalizeHost("[::1]"); got != "::1" {
		t.Fatalf("NormalizeHost = %q", got)
	}
}

// TestDeltaLeavesICMPChecksumAlone guards a subtle rewrite bug: an ICMPv4
// checksum covers the ICMP message only, so rewriting the IP addresses must not
// change it. Only fields inside the message may move it.
func TestDeltaLeavesICMPChecksumAlone(t *testing.T) {
	oldSrc := net.IPv4(10, 0, 0, 1)
	newSrc := net.IPv4(10, 0, 0, 200)

	icmp := []byte{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 'p', 'i', 'n', 'g'}
	binary.BigEndian.PutUint16(icmp[2:], ^FoldChecksum(SumWords(0, icmp)))
	before := binary.BigEndian.Uint16(icmp[2:])

	var d Delta
	d.ReplaceAddr(oldSrc, newSrc) // an address rewrite touches no ICMP field
	if err := PatchTransportChecksum(ProtoICMP, icmp, &d); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if got := binary.BigEndian.Uint16(icmp[2:]); got != before {
		t.Fatalf("ICMP checksum moved on an address-only rewrite: %#04x -> %#04x", before, got)
	}

	// Rewriting the echo identifier is an in-message change and must be applied.
	var d2 Delta
	d2.Replace(0x1234, 0x5678)
	if err := PatchTransportChecksum(ProtoICMP, icmp, &d2); err != nil {
		t.Fatalf("patch: %v", err)
	}
	changed := binary.BigEndian.Uint16(icmp[2:])
	if changed == before {
		t.Fatal("ICMP checksum did not follow an identifier rewrite")
	}
	// Verify against a full recomputation with the new identifier.
	ref := []byte{8, 0, 0, 0, 0x56, 0x78, 0x00, 0x01, 'p', 'i', 'n', 'g'}
	want := ^FoldChecksum(SumWords(0, ref))
	if changed != want {
		t.Fatalf("ICMP checksum = %#04x, want %#04x", changed, want)
	}
}

// TestUDPChecksumlessStaysChecksumless covers RFC 768: a zero UDP checksum means
// "not computed" and must not be invented.
func TestUDPChecksumlessStaysChecksumless(t *testing.T) {
	oldSrc := net.IPv4(10, 0, 0, 1)
	newSrc := net.IPv4(10, 0, 0, 200)

	udp := make([]byte, 8+4)
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 4000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], "data")

	var d Delta
	d.ReplaceAddr(oldSrc, newSrc)
	if err := PatchTransportChecksum(ProtoUDP, udp, &d); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if got := binary.BigEndian.Uint16(udp[6:8]); got != 0 {
		t.Fatalf("zero UDP checksum was replaced by %#04x", got)
	}

	// A computed checksum must still be updated.
	binary.BigEndian.PutUint16(udp[6:8], Recompute(oldSrc, net.IPv4(10, 0, 0, 9), ProtoUDP, udp))
	base := binary.BigEndian.Uint16(udp[6:8])
	if err := PatchTransportChecksum(ProtoUDP, udp, &d); err != nil {
		t.Fatalf("patch: %v", err)
	}
	got := binary.BigEndian.Uint16(udp[6:8])
	ref := append([]byte(nil), udp...)
	ref[6], ref[7] = 0, 0
	if want := Recompute(newSrc, net.IPv4(10, 0, 0, 9), ProtoUDP, ref); got != want {
		t.Fatalf("UDP checksum = %#04x, want %#04x (was %#04x)", got, want, base)
	}
}

// TestSCTPPatchRefusesIncrementalUpdate checks that a CRC32c is never patched
// incrementally, which would silently corrupt it.
func TestSCTPPatchRefusesIncrementalUpdate(t *testing.T) {
	payload := make([]byte, 24)
	binary.BigEndian.PutUint16(payload[0:2], 1234)
	binary.BigEndian.PutUint16(payload[2:4], 4321)
	binary.BigEndian.PutUint32(payload[4:8], 1)
	if err := RecomputeSCTP(payload); err != nil {
		t.Fatalf("RecomputeSCTP: %v", err)
	}
	before := append([]byte(nil), payload[8:12]...)

	var d Delta
	d.ReplaceAddr(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
	err := PatchTransportChecksum(ProtoSCTP, payload, &d)
	if err == nil {
		t.Fatal("an incremental patch of SCTP must be refused")
	}
	if !bytes.Equal(payload[8:12], before) {
		t.Fatal("the CRC field was modified by a refused patch")
	}
}

// TestListenTCPIsDualStack checks a wildcard TCP listener serves both IPv4 and
// IPv6 loopback. Windows resolves "localhost" to ::1 first, and the bundled ssh
// client does not fall back to 127.0.0.1, so an IPv4-only listener makes
// `ssh localhost -p <port>` fail even though the forwarder works.
func TestListenTCPIsDualStack(t *testing.T) {
	port := freeTCPPort(t)
	ln, err := ListenTCP("", port)
	if err != nil {
		t.Fatalf("ListenTCP wildcard: %v", err)
	}
	defer ln.Close()

	done := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			done <- c.RemoteAddr().String()
			_ = c.Close()
		}
	}()

	for _, target := range []string{HostPort("127.0.0.1", port), HostPort("::1", port)} {
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			t.Errorf("dial %s through a wildcard listener failed: %v", target, err)
			continue
		}
		_ = c.Close()
		select {
		case who := <-done:
			t.Logf("%s served a connection from %s", target, who)
		case <-time.After(2 * time.Second):
			t.Errorf("%s: the listener accepted nothing", target)
		}
	}
}

// TestListenTCPReportsPortConflict checks a port already held by another program
// is refused instead of silently shared between two sockets.
func TestListenTCPReportsPortConflict(t *testing.T) {
	other, err := net.Listen("tcp4", HostPort("", 0))
	if err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	defer other.Close()
	port := other.Addr().(*net.TCPAddr).Port

	ln, err := ListenTCP("", port)
	if err == nil {
		_ = ln.Close()
		t.Fatal("ListenTCP accepted a port that another program already holds")
	}
	if !isAddrInUse(err) {
		t.Fatalf("error does not identify the conflict: %v", err)
	}
	t.Logf("conflict reported as: %v", err)
}

// TestListenUDPIsDualStack is the UDP counterpart of TestListenTCPIsDualStack.
func TestListenUDPIsDualStack(t *testing.T) {
	port := freeUDPPort(t)
	pc, err := ListenUDP("", port)
	if err != nil {
		t.Fatalf("ListenUDP wildcard: %v", err)
	}
	defer pc.Close()

	// The socket has to answer so the client can prove which family its datagram
	// travelled over.
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	for _, target := range []string{HostPort("127.0.0.1", port), HostPort("::1", port)} {
		raddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			t.Fatalf("resolve %s: %v", target, err)
		}
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			t.Errorf("dial %s through a wildcard UDP socket failed: %v", target, err)
			continue
		}
		_, _ = c.Write([]byte("probe"))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 32)
		n, err := c.Read(buf)
		if err != nil {
			t.Errorf("%s: the wildcard UDP socket received nothing: %v", target, err)
		} else if string(buf[:n]) != "echo:probe" {
			t.Errorf("%s: reply = %q", target, buf[:n])
		} else {
			t.Logf("%s: datagram round-tripped", target)
		}
		_ = c.Close()
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}
