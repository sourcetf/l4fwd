package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// clientKey identifies a client flow: its address plus whichever of port or
// protocol identifier identifies it. The fields are comparable values rather than
// a built string, so a lookup costs no allocation.
type clientKey struct {
	ip    [4]byte
	port  uint16
	ident uint16
}

// replyKey identifies a reply flow: the address the reply came from plus the
// proxy port or identifier used towards it.
type replyKey struct {
	ip    [4]byte
	port  uint16
	ident uint16
}

// fragmentKey identifies the datagram a non-initial fragment belongs to.
type fragmentKey struct {
	ip   [4]byte
	id   uint16
	side uint8 // 0 = from the client, 1 = from the target
}

// rawSession tracks one client conversation handled at the IP layer.
type rawSession struct {
	key         clientKey
	reply       replyKey
	clientIP    net.IP
	clientPort  uint16 // 0 when the protocol has no ports
	clientIdent uint16 // 0 when the protocol has no identifier
	proxyPort   uint16 // port we impersonate towards the target
	proxyIdent  uint16 // identifier we impersonate towards the target
	viaIP       net.IP // address the client targeted, used as reply source
	targetIP    net.IP
	targetPort  uint16
	lastSeen    atomic.Int64
	packets     atomic.Int64
	bytes       atomic.Int64
	closed      atomic.Bool
}

func (s *rawSession) touch() { s.lastSeen.Store(time.Now().UnixNano()) }

func (s *rawSession) idle() time.Duration {
	return time.Since(time.Unix(0, s.lastSeen.Load()))
}

// packetSender abstracts the raw send socket so tests can substitute a fake.
type packetSender interface {
	Send(pkt []byte, dst net.IP) error
	Close() error
}

// RawListener implements an IP layer relay: it captures packets for one IP
// protocol that arrive at this machine and re-emits them towards the target
// with rewritten addresses (and ports/identifiers when the protocol has them),
// then maps the replies back to the original client. Because it never looks
// past the transport header, protocols that exist only in the client's own
// implementation work exactly like standard ones.
type RawListener struct {
	rule  *config.Rule
	set   config.Settings
	st    *stats.RuleStats
	log   *logx.Logger
	proto uint8

	cap  *netutil.RawSock // capture socket
	send packetSender     // send socket with IP_HDRINCL

	// poller/wake let this listener share one WSAPoll call with its siblings
	// instead of parking in its own. nil means "poll on my own", which is what a
	// standalone raw rule does.
	poller   *rawPollSet
	wake     <-chan struct{}
	unpolled func()

	// sendIP is the address we put in the source field of forwarded packets.
	sendIP net.IP
	// listenIPs are the addresses considered "ours" for matching.
	listenIPs []net.IP
	// matchAnyDst is set when the rule sniffed traffic addressed elsewhere.
	matchAnyDst bool

	// target caches the resolved target address (nil until resolved).
	target   net.IP
	targetMu sync.Mutex

	done   chan struct{}
	closeO sync.Once
	wg     sync.WaitGroup

	mu       sync.RWMutex
	byClient map[clientKey]*rawSession // client flow -> session
	byReply  map[replyKey]*rawSession  // reply flow -> session
	// fragments maps an in-flight fragmented datagram to its session. Keyed by the
	// source address, IP ID and direction, because non-initial fragments carry no
	// transport header and cannot be demultiplexed on their own.
	fragments map[fragmentKey]*rawSession

	portPool *portAllocator
	stopOnce sync.Once
	ttl      time.Duration

	// sessionLimit caps the session table. Raw sessions cannot be told apart from
	// legitimate clients (a flood only has to invent source addresses or ports),
	// so the table needs a ceiling: each entry pins a proxy port, buffers and a
	// reply goroutine. It is derived from the configured budget and can be raised
	// per rule with maxConns.
	sessionLimit int
	denied       atomic.Int64

	// sent remembers our own egress packets so a capture echo cannot loop.
	sent *sentRing

	// out is the scratch buffer the current packet is rewritten into. One buffer
	// per listener is enough because handlePacket runs on that listener's own
	// capture goroutine, and pooling it keeps the relay from allocating (and
	// zeroing) a packet-sized buffer for every packet it forwards.
	out []byte
}

// Raw session limits. A raw session costs a proxy port plus bookkeeping, and the
// port pool is the scarce resource: 20000 proxies exist, so the table is capped
// well below that.
const (
	// rawSessionMemoryBudget is the session budget for the bookkeeping of a raw
	// rule when maxConns is not set. One session is a few hundred bytes plus a
	// proxy port, so the default is generous but finite.
	rawSessionMemoryBudget = 4096
	// rawSessionMaxCeiling bounds an explicit maxConns so a typo cannot make the
	// table unbounded.
	rawSessionMaxCeiling = 16384
)

// NewRawListener prepares a raw IP relay for the rule.
func NewRawListener(rule *config.Rule, set config.Settings, st *stats.RuleStats, log *logx.Logger) (*RawListener, error) {
	num, err := config.ProtocolNumber(rule.Protocol)
	if err != nil {
		return nil, err
	}
	if num > 255 {
		return nil, fmt.Errorf("protocol number %d out of range", num)
	}
	r := &RawListener{
		rule:      rule,
		set:       set,
		st:        st,
		log:       log,
		proto:     uint8(num),
		done:      make(chan struct{}),
		byClient:  map[clientKey]*rawSession{},
		byReply:   map[replyKey]*rawSession{},
		fragments: map[fragmentKey]*rawSession{},
		portPool:  newPortAllocator(40000, 60000),
		ttl:       rule.UDPSessionTTL(set),
		sent:      newSentRing(4096),
	}
	r.sessionLimit = rawSessionMemoryBudget
	if rule.MaxConns > 0 {
		r.sessionLimit = rule.MaxConns
	}
	if r.sessionLimit > rawSessionMaxCeiling {
		r.sessionLimit = rawSessionMaxCeiling
	}
	// Raw sessions need a lifetime even when the rule only sets an idle
	// timeout; fall back to the UDP session TTL.
	if r.ttl <= 0 {
		r.ttl = 120 * time.Second
	}
	return r, nil
}

// Start opens the sockets and begins capturing.
func (r *RawListener) Start() error {
	if ip := r.rule.SourceIP; ip != "" {
		parsed := net.ParseIP(ip).To4()
		if parsed == nil {
			return fmt.Errorf("source IP %q must be IPv4", ip)
		}
		r.sendIP = parsed
	}

	bindIP := net.IP(nil)
	if !netutil.IsWildcardHost(r.rule.ListenHost) {
		parsed := net.ParseIP(r.rule.ListenHost).To4()
		if parsed == nil {
			return fmt.Errorf("listen address %q must be IPv4", r.rule.ListenHost)
		}
		bindIP = parsed
	}

	cap, err := netutil.OpenRawSock(netutil.RawSockOptions{
		Proto:       int(r.proto),
		BindIP:      bindIP,
		Sniff:       r.rule.Sniff,
		HeaderIncl:  true,
		RcvBufBytes: r.set.BufferKB * 1024,
	})
	if err != nil {
		return fmt.Errorf("capture socket: %w", err)
	}
	r.cap = cap

	if r.sendIP == nil {
		r.sendIP = defaultSendIP(bindIP)
	}
	if r.sendIP == nil {
		cap.Close()
		return errors.New("no usable local IPv4 address found for sending; set a source IP on the rule")
	}

	snd, err := netutil.OpenRawSock(netutil.RawSockOptions{
		Proto:       int(r.proto),
		BindIP:      r.sendIP,
		HeaderIncl:  true,
		SendOnly:    true,
		SndBufBytes: r.set.BufferKB * 1024,
	})
	if err != nil {
		cap.Close()
		return fmt.Errorf("send socket: %w", err)
	}
	r.send = snd

	// Addresses that count as "this machine" when matching incoming packets.
	r.listenIPs = []net.IP{}
	if bindIP != nil {
		r.listenIPs = append(r.listenIPs, bindIP)
	} else {
		r.listenIPs = append(r.listenIPs, net.IPv4zero)
		r.listenIPs = append(r.listenIPs, netutil.LocalIPv4s()...)
	}
	r.matchAnyDst = r.rule.Sniff

	// Join the shared poller when the rule runs many protocols at once: one
	// WSAPoll call then covers all of them instead of one parked call per socket.
	if r.poller != nil {
		r.wake, r.unpolled = r.poller.register(r.cap.FD())
	}

	mode := "local"
	if r.rule.Sniff {
		mode = "promiscuous"
	}
	r.log.Infof("raw", "protocol %d (%s) listening on %s, forwarding to %s, %s capture, source %s",
		r.proto, config.ProtocolName(int(r.proto)), listenDesc(r.rule), targetDesc(r.rule), mode, r.sendIP)

	r.wg.Add(2)
	go r.captureLoop()
	go r.reapLoop()
	return nil
}

func listenDesc(rule *config.Rule) string {
	if netutil.IsWildcardHost(rule.ListenHost) {
		return "0.0.0.0"
	}
	if rule.ListenPort > 0 && netutil.IsPortLike(0) {
		return netutil.HostPort(rule.ListenHost, rule.ListenPort)
	}
	if rule.ListenPort > 0 {
		return netutil.HostPort(rule.ListenHost, rule.ListenPort)
	}
	return rule.ListenHost
}

func targetDesc(rule *config.Rule) string {
	if rule.TargetPort > 0 {
		return netutil.HostPort(rule.TargetHost, rule.TargetPort)
	}
	return rule.TargetHost
}

// defaultSendIP picks the local address used as the source of forwarded
// packets: the interface address that routes towards the target when possible.
func defaultSendIP(bindIP net.IP) net.IP {
	if bindIP != nil && !bindIP.IsUnspecified() {
		return bindIP
	}
	if ips := netutil.LocalIPv4s(); len(ipv4Only(ips)) > 0 {
		out := ipv4Only(ips)
		// Prefer a non link local address, matching the common LAN case.
		for _, ip := range out {
			if !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
		return out[0]
	}
	return nil
}

func ipv4Only(ips []net.IP) []net.IP {
	out := ips[:0]
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, ip)
		}
	}
	return out
}

func (r *RawListener) captureLoop() {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	if r.unpolled != nil {
		defer r.unpolled()
	}
	for {
		select {
		case <-r.done:
			return
		default:
		}
		// Wait for the socket to have data. A listener that shares a poller waits
		// on its wakeup channel; a standalone one parks in WSAPoll itself. Both
		// keep an idle relay at zero CPU while noticing shutdown within one poll
		// interval, and both bound the wait so a closed socket is noticed.
		if r.wake != nil {
			select {
			case <-r.done:
				return
			case <-r.wake:
			}
		} else {
			ready, err := r.cap.WaitReadable(pollSetInterval.ms())
			if err != nil {
				select {
				case <-r.done:
					return
				default:
				}
				r.log.Warnf("raw", "poll error: %v", err)
				r.st.Error("poll: " + err.Error())
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if !ready {
				continue
			}
		}
		for i := 0; i < 256; i++ { // drain the burst, then wait again
			pkt, err := r.cap.ReceivePacket(buf)
			if err != nil {
				if netutil.WouldBlock(err) {
					break
				}
				select {
				case <-r.done:
					return
				default:
				}
				r.log.Warnf("raw", "capture error: %v", err)
				r.st.Error("capture: " + err.Error())
				break
			}
			if len(pkt) < 20 {
				continue
			}
			// handlePacket only reads its input (the forwarded copy is a separate
			// buffer), so the captured bytes are used in place and reused on the
			// next iteration.
			r.handlePacket(pkt)
		}
	}
}

// handlePacket decides whether the packet belongs to the client side or the
// target side, rewrites it and re-emits it.
func (r *RawListener) handlePacket(pkt []byte) {
	h, err := netutil.ParseHeader(pkt)
	if err != nil {
		return
	}
	if h.Proto != r.proto {
		return
	}
	payload := pkt[h.IHL:]

	// A non-initial fragment carries no transport header, so it can only be
	// placed through the fragment table filled in by the first fragment.
	if h.FragOff != 0 {
		r.forwardFragment(pkt, h, payload)
		return
	}

	// Target side: the packet came back from the target (or from a host we
	// forwarded to) and must be mapped to the client that started the flow.
	if r.isFromTarget(h) {
		r.handleReply(pkt, h, payload)
		return
	}
	// Client side: the packet is addressed to this machine (or, in
	// promiscuous mode, to an address we are standing in for).
	if !r.matchesClient(h, payload) {
		return
	}
	r.handleClient(pkt, h, payload)
}

// forwardFragment relays a non-initial fragment using the session registered by
// the datagram's first fragment.
func (r *RawListener) forwardFragment(pkt []byte, h *netutil.Header, payload []byte) {
	dir, sess := r.lookupFragment(h)
	if sess == nil {
		return
	}
	sess.touch()
	var err error
	if dir == fragSideClient {
		err = r.rewriteToTarget(pkt, h, payload, sess)
	} else {
		err = r.rewriteToClient(pkt, h, payload, sess)
	}
	if err != nil {
		r.st.Error("fragment rewrite: " + err.Error())
		return
	}
	dst := sess.targetIP
	statsDir := stats.DirIn
	if dir != fragSideClient {
		dst = sess.clientIP
		statsDir = stats.DirOut
	}
	out := r.out
	if err := r.send.Send(out, dst); err != nil {
		r.st.Error("fragment send: " + err.Error())
		r.st.Drop(1)
		return
	}
	r.rememberSent(out)
	sess.packets.Add(1)
	sess.bytes.Add(int64(len(out)))
	r.st.RecordPacket(statsDir, int64(len(out)), true)
}

// Fragment table sides.
const (
	fragSideClient uint8 = 0
	fragSideReply  uint8 = 1
)

// rememberFragment records the session for later fragments of the same
// datagram (identified by source address and IP ID, which the relay preserves).
func (r *RawListener) rememberFragment(side uint8, src []byte, id uint16, sess *rawSession) {
	const maxEntries = 4096
	var key fragmentKey
	key.side = side
	key.id = id
	copy(key.ip[:], src)
	r.mu.Lock()
	if len(r.fragments) >= maxEntries {
		// A flood of never completed datagrams must not grow this table.
		r.fragments = map[fragmentKey]*rawSession{}
	}
	r.fragments[key] = sess
	r.mu.Unlock()
}

func (r *RawListener) lookupFragment(h *netutil.Header) (uint8, *rawSession) {
	var key fragmentKey
	key.id = h.ID
	copy(key.ip[:], h.Src4())
	r.mu.RLock()
	defer r.mu.RUnlock()
	key.side = fragSideClient
	if s, ok := r.fragments[key]; ok {
		return fragSideClient, s
	}
	key.side = fragSideReply
	if s, ok := r.fragments[key]; ok {
		return fragSideReply, s
	}
	return fragSideClient, nil
}

func (r *RawListener) isFromTarget(h *netutil.Header) bool {
	target := r.targetIP()
	if target != nil && netutil.SameIP(h.Src, target) {
		return true
	}
	// Fall back to the reply table so hosts behind the target address (or a
	// target whose exact address we no longer match) still resolve.
	return r.lookupReply(h, nil) != nil
}

func (r *RawListener) targetIP() net.IP {
	r.targetMu.Lock()
	defer r.targetMu.Unlock()
	if r.target == nil {
		if ip, err := netutil.ResolveIPv4(r.rule.TargetHost); err == nil {
			r.target = ip
		}
	}
	return r.target
}

func (r *RawListener) matchesClient(h *netutil.Header, payload []byte) bool {
	// A packet we emitted ourselves must never be picked up again, or the relay
	// would loop: every captured copy would be forwarded once more. This check
	// runs before the promiscuous short cut, because a sniffing relay sees its
	// own egress traffic too.
	if r.isOwnEgress(h, payload) {
		return false
	}
	if r.matchAnyDst {
		// Promiscuous capture: we take over traffic to any destination.
		return true
	}
	if !r.isOurAddress(h.Dst) {
		return false
	}
	if r.rule.ListenPort > 0 && r.portMode() != portsNone {
		_, dstPort, ok := r.readPorts(payload)
		if !ok || dstPort != uint16(r.rule.ListenPort) {
			return false
		}
	}
	return true
}

// isOwnEgress reports whether the packet is one of ours coming back on the
// capture socket. Two shapes are recognised:
//
//	src = our send address, dst = the target      → our forwarded copy
//	src = our send address, port/id = our proxy   → a reply we sent to a client
//
// As a backstop it also matches a packet we transmitted moments ago, so an echo
// that slips past the two rules above cannot start an amplification loop.
//
// Everything the relay puts on the wire has our send address as its source, so a
// packet from anyone else returns immediately: that keeps the cost of this check
// off the path of ordinary traffic, which is most of what a promiscuous capture
// sees.
func (r *RawListener) isOwnEgress(h *netutil.Header, payload []byte) bool {
	if r.sendIP == nil || !netutil.SameIP(h.Src, r.sendIP) {
		return false
	}
	if target := r.targetIP(); target != nil && netutil.SameIP(h.Dst, target) {
		return true
	}
	if r.isProxyPort(h, payload) {
		return true
	}
	return r.sentSeen(h, payload)
}

// sentRing remembers the last packets the relay transmitted. Entries age out
// quickly: only a copy that comes back within the capture latency is an echo.
//
// It is a ring of fixed size entries rather than a map because it sits on the
// per-packet path: keys are comparable structs (no string building, no
// allocation) and a lookup is a short linear scan of at most sentRingSize
// entries, all of which stay in cache.
type sentRing struct {
	mu   sync.Mutex
	keys []sentKey
	at   []int64 // unix nanoseconds
	next int
	full bool
}

// sentRingSize is how many recent transmissions are remembered. A capture echo
// arrives within milliseconds of the transmission, so this covers every case that
// matters (at 100k packets/s it is still ~5 ms of history) while keeping the scan
// short. It is only consulted for packets whose source is our own send address,
// which is a small fraction of what a capture socket sees.
const sentRingSize = 512

// sentKey identifies a transmitted packet. Addresses are stored as four bytes so
// the struct stays comparable and allocation free.
type sentKey struct {
	proto uint8
	src   [4]byte
	dst   [4]byte
	srcP  uint16
	dstP  uint16
	id    uint16
}

func newSentRing(_ int) *sentRing {
	return &sentRing{
		keys: make([]sentKey, sentRingSize),
		at:   make([]int64, sentRingSize),
	}
}

func (s *sentRing) remember(k sentKey) {
	now := time.Now().UnixNano()
	s.mu.Lock()
	s.keys[s.next] = k
	s.at[s.next] = now
	s.next++
	if s.next == len(s.keys) {
		s.next = 0
		s.full = true
	}
	s.mu.Unlock()
}

func (s *sentRing) seen(k sentKey) bool {
	// Only recent entries count: a copy that comes back after the window is a
	// different packet reusing the same identifiers, not an echo.
	cutoff := time.Now().Add(-sentRingWindow).UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.next
	if s.full {
		n = len(s.keys)
	}
	for i := 0; i < n; i++ {
		if s.keys[i] == k && s.at[i] >= cutoff {
			return true
		}
	}
	return false
}

// sentRingWindow is how long a remembered transmission can produce a match.
const sentRingWindow = 2 * time.Second

// sentKeyFor builds the ring key of a packet, reading ports only when the rule
// translates them.
func (r *RawListener) sentKeyFor(h *netutil.Header, payload []byte) sentKey {
	k := sentKey{proto: h.Proto, id: h.ID}
	copy(k.src[:], h.Src4())
	copy(k.dst[:], h.Dst4())
	if r.portMode() != portsNone {
		if src, dst, ok := r.readPorts(payload); ok {
			k.srcP, k.dstP = src, dst
		}
	}
	return k
}

// rememberSent records a packet the relay just transmitted, so that a capture
// echo of it is recognised even when the two cheap shapes in isOwnEgress do not
// cover it (a local target, a proxy port that was reused, a promiscuous rule).
//
// It reads the outgoing packet directly instead of going through a parsed
// header: this runs for every forwarded packet, and the fields it needs are at
// fixed offsets.
func (r *RawListener) rememberSent(out []byte) {
	if r.sent == nil || len(out) < 20 {
		return
	}
	k := sentKey{proto: out[9], id: binary.BigEndian.Uint16(out[4:6])}
	copy(k.src[:], out[12:16])
	copy(k.dst[:], out[16:20])
	if hdrLen := int(out[0]&0x0f) * 4; r.portMode() != portsNone && hdrLen <= len(out) {
		if src, dst, ok := r.readPorts(out[hdrLen:]); ok {
			k.srcP, k.dstP = src, dst
		}
	}
	r.sent.remember(k)
}

// sentSeen reports whether the packet matches one we just transmitted.
func (r *RawListener) sentSeen(h *netutil.Header, payload []byte) bool {
	if r.sent == nil {
		return false
	}
	return r.sent.seen(r.sentKeyFor(h, payload))
}

// portMode says where (if anywhere) a rule's port pair lives.
type portMode int

const (
	// portsNone: the protocol carries no ports at all (GRE, ESP, plain ICMP).
	portsNone portMode = iota
	// portsTransport: ports are part of the transport header (TCP, UDP, SCTP...).
	portsTransport
	// portsPayload: ports are the first four bytes of a bespoke protocol's
	// payload, as raw socket implementations commonly define them.
	portsPayload
)

// portMode resolves how this rule reads and writes ports.
func (r *RawListener) portMode() portMode {
	if netutil.IsPortLike(r.proto) {
		return portsTransport
	}
	if r.rule.PayloadPorts {
		return portsPayload
	}
	return portsNone
}

// readPorts extracts the source and destination port of a packet's payload.
func (r *RawListener) readPorts(payload []byte) (src, dst uint16, ok bool) {
	switch r.portMode() {
	case portsTransport:
		return netutil.Ports(r.proto, payload)
	case portsPayload:
		return netutil.PortsIn(payload)
	}
	return 0, 0, false
}

// writePorts rewrites the port pair in place; zero arguments are preserved.
func (r *RawListener) writePorts(payload []byte, src, dst uint16) {
	switch r.portMode() {
	case portsTransport:
		netutil.SetPorts(payload, r.proto, src, dst)
	case portsPayload:
		netutil.SetPortsIn(payload, src, dst)
	}
}

func (r *RawListener) isOurAddress(ip []byte) bool {
	same := netutil.SameIP
	for _, l := range r.listenIPs {
		if l.IsUnspecified() || same(l, ip) {
			return true
		}
	}
	return false
}

// flowOf reports the identity a packet is demultiplexed on. For bespoke
// protocols configured with payload ports this is the port pair at the start of
// the payload; otherwise it falls back to the protocol's own header fields.
func (r *RawListener) flowOf(payload []byte) (netutil.FlowIdentity, bool) {
	if r.portMode() == portsPayload {
		src, dst, ok := netutil.PortsIn(payload)
		if !ok {
			return netutil.FlowIdentity{}, false
		}
		return netutil.FlowIdentity{SrcPort: src, DstPort: dst, HasPorts: true}, true
	}
	return netutil.ParseFlow(r.proto, payload)
}

func (r *RawListener) handleClient(pkt []byte, h *netutil.Header, payload []byte) {
	target := r.targetIP()
	if target == nil {
		r.st.Error("cannot resolve target " + r.rule.TargetHost)
		return
	}
	if target != nil && netutil.SameIP(h.Src, target) && netutil.SameIP(h.Dst, r.sendIP) {
		return // our own forwarded packet seen back on the capture socket
	}
	ident, hasIdent := r.flowOf(payload)

	sess, isNew := r.sessionFor(h, ident, hasIdent)
	if sess == nil {
		return
	}
	if isNew {
		r.st.ConnAccepted()
		r.st.ConnOpened()
		r.log.Debugf("raw", "session %s -> %s", sess.describe(), targetDesc(r.rule))
	}
	sess.touch()
	sess.packets.Add(1)
	sess.bytes.Add(int64(len(pkt)))
	// Later fragments of this datagram are matched by source address and IP ID.
	if h.Flags&netutil.FlagMF != 0 {
		r.rememberFragment(fragSideClient, h.Src4(), h.ID, sess)
	}

	if err := r.rewriteToTarget(pkt, h, payload, sess); err != nil {
		r.st.Error("rewrite: " + err.Error())
		r.log.Debugf("raw", "drop packet from %s: %v", h.SrcIP(), err)
		return
	}
	out := r.out
	if err := r.send.Send(out, target); err != nil {
		r.st.Error("send to target: " + err.Error())
		r.st.Drop(1)
		return
	}
	r.rememberSent(out)
	r.st.RecordPacket(stats.DirIn, int64(len(out)), true)
}

// rewriteToTarget rewrites addresses (and ports/identifiers) of a client
// packet so it looks like it originates from this machine towards the target.
//
// The result goes into the listener's scratch buffer (r.out), which the caller
// sends and then returns to the pool; that is why this returns an error rather
// than a slice. Nothing may hold on to r.out past the send.
func (r *RawListener) rewriteToTarget(pkt []byte, h *netutil.Header, payload []byte, sess *rawSession) error {
	out := r.forwardBuf(len(pkt))
	copy(out, pkt)
	hdrLen := h.IHL
	op := out[hdrLen:]

	// IP header: source becomes us, destination becomes the target.
	copy(out[12:16], r.sendIP.To4())
	copy(out[16:20], sess.targetIP.To4())
	if r.rule.TTL > 0 {
		out[8] = uint8(r.rule.TTL)
	}
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], netutil.Checksum(out[:hdrLen]))

	// Only the first fragment carries the transport header (and its checksum).
	if h.FragOff != 0 {
		r.out = out
		return nil
	}

	// The old addresses are read from the captured packet, which is a different
	// buffer from out, so nothing has to be copied out of the way first.
	delta := &netutil.Delta{}
	delta.ReplaceAddr(h.Src4(), r.sendIP)
	delta.ReplaceAddr(h.Dst4(), sess.targetIP)

	if r.portMode() != portsNone {
		srcPort, dstPort, ok := r.readPorts(op)
		if ok {
			newSrc, newDst := srcPort, dstPort
			if sess.proxyPort != 0 {
				newSrc = sess.proxyPort
			}
			if r.rule.TargetPort > 0 {
				newDst = uint16(r.rule.TargetPort)
			}
			r.writePorts(op, newSrc, newDst)
			if netutil.Kind(r.proto) == netutil.ChecksumPseudo || netutil.Kind(r.proto) == netutil.ChecksumMessageOnly {
				if newSrc != srcPort {
					delta.Replace(srcPort, newSrc)
				}
				if newDst != dstPort {
					delta.Replace(dstPort, newDst)
				}
			}
		}
	} else if sess.proxyIdent != 0 {
		old := sess.clientIdent
		netutil.SetIdent(op, r.proto, sess.proxyIdent)
		if old != 0 && old != sess.proxyIdent {
			delta.Replace(old, sess.proxyIdent)
		}
	}

	if err := r.fixChecksum(h, op, delta); err != nil {
		return err
	}
	r.out = out
	return nil
}

// fixChecksum repairs the transport checksum of a rewritten packet.
//
// Two situations have no purely incremental repair and are handled here so both
// rewrite paths behave identically:
//
//   - a datagram too short to contain the checksum field is forwarded as is;
//   - SCTP carries a CRC32c, which has no one's-complement incremental update:
//     it is recomputed over the whole datagram. A fragment cannot be repaired
//     without its siblings, so it is passed through unchanged.
func (r *RawListener) fixChecksum(h *netutil.Header, payload []byte, delta *netutil.Delta) error {
	if netutil.Kind(r.proto) == netutil.ChecksumCRC32c {
		if !h.IsFragment() {
			_ = netutil.RecomputeSCTP(payload)
		}
		return nil
	}
	err := netutil.PatchTransportChecksum(r.proto, payload, delta)
	if err != nil && !errors.Is(err, netutil.ErrShortSegment) {
		return err
	}
	return nil
}

func (r *RawListener) handleReply(pkt []byte, h *netutil.Header, payload []byte) {
	sess := r.lookupReply(h, payload)
	if sess == nil {
		return
	}
	sess.touch()
	if h.Flags&netutil.FlagMF != 0 {
		r.rememberFragment(fragSideReply, h.Src4(), h.ID, sess)
	}
	if err := r.rewriteToClient(pkt, h, payload, sess); err != nil {
		r.st.Error("reply rewrite: " + err.Error())
		return
	}
	out := r.out
	if err := r.send.Send(out, sess.clientIP); err != nil {
		r.st.Error("send to client: " + err.Error())
		r.st.Drop(1)
		return
	}
	r.rememberSent(out)
	sess.packets.Add(1)
	sess.bytes.Add(int64(len(out)))
	r.st.RecordPacket(stats.DirOut, int64(len(out)), true)
}

// rewriteToClient does the mirror image for packets coming back from the target.
// Like rewriteToTarget it writes into the listener's scratch buffer and reports
// failure without a slice.
func (r *RawListener) rewriteToClient(pkt []byte, h *netutil.Header, payload []byte, sess *rawSession) error {
	out := r.forwardBuf(len(pkt))
	copy(out, pkt)
	hdrLen := h.IHL
	op := out[hdrLen:]

	copy(out[12:16], sess.viaIP.To4()) // the address the client originally targeted
	copy(out[16:20], sess.clientIP.To4())
	if r.rule.TTL > 0 {
		out[8] = uint8(r.rule.TTL)
	}
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], netutil.Checksum(out[:hdrLen]))

	if h.FragOff != 0 {
		r.out = out
		return nil
	}

	// As in rewriteToTarget: the original addresses are read from the captured
	// packet, not from the copy being modified.
	delta := &netutil.Delta{}
	delta.ReplaceAddr(h.Src4(), sess.viaIP)
	delta.ReplaceAddr(h.Dst4(), sess.clientIP)

	if r.portMode() != portsNone {
		srcPort, dstPort, ok := r.readPorts(op)
		if ok {
			newSrc, newDst := srcPort, dstPort
			if r.rule.TargetPort > 0 && sess.targetPort != 0 {
				newSrc = sess.targetPort
			}
			if sess.clientPort != 0 {
				newDst = sess.clientPort
			}
			r.writePorts(op, newSrc, newDst)
			if netutil.Kind(r.proto) == netutil.ChecksumPseudo || netutil.Kind(r.proto) == netutil.ChecksumMessageOnly {
				if newSrc != srcPort {
					delta.Replace(srcPort, newSrc)
				}
				if newDst != dstPort {
					delta.Replace(dstPort, newDst)
				}
			}
		}
	} else if sess.proxyIdent != 0 {
		netutil.SetIdent(op, r.proto, sess.clientIdent)
		delta.Replace(sess.proxyIdent, sess.clientIdent)
	}

	if err := r.fixChecksum(h, op, delta); err != nil {
		return err
	}
	r.out = out
	return nil
}

// forwardBuf returns the scratch buffer the rewritten packet goes into, growing it
// when a packet does not fit. Steady state it allocates nothing: the same buffer
// is reused for every forwarded packet, which is what keeps a busy raw rule from
// paying an allocation (and a zeroing) per packet. It lives with the listener, so
// the cost is a few KiB per raw listener.
func (r *RawListener) forwardBuf(n int) []byte {
	if cap(r.out) < n {
		r.out = make([]byte, n)
	}
	return r.out[:n]
}

// sessionFor finds or creates the session a client packet belongs to.
func (r *RawListener) sessionFor(h *netutil.Header, ident netutil.FlowIdentity, hasIdent bool) (*rawSession, bool) {
	key := r.clientKey(h, ident, hasIdent)
	r.mu.RLock()
	sess := r.byClient[key]
	r.mu.RUnlock()
	if sess != nil {
		return sess, false
	}

	target := r.targetIP()
	if target == nil {
		return nil, false
	}
	s := &rawSession{
		key:        key,
		clientIP:   net.IP(append([]byte(nil), h.Src4()...)),
		targetIP:   target,
		viaIP:      net.IP(append([]byte(nil), h.Dst4()...)),
		targetPort: uint16(r.rule.TargetPort),
	}
	if hasIdent {
		if ident.HasPorts {
			s.clientPort = ident.SrcPort
			if r.rule.TargetPort == 0 {
				s.targetPort = ident.DstPort
			}
			s.proxyPort = r.portPool.alloc()
		}
		if ident.HasIdent {
			s.clientIdent = ident.Ident
			s.proxyIdent = r.portPool.alloc()
			if s.proxyIdent == 0 {
				s.proxyIdent = 1
			}
		}
	}
	s.reply = r.replyKeyOf(s)
	s.touch()

	r.mu.Lock()
	if ex, ok := r.byClient[key]; ok {
		r.mu.Unlock()
		return ex, false
	}
	// A raw flood only has to invent source addresses or ports, so the table is
	// capped: without this, each invented client would pin a proxy port, its
	// mappings and its buffers until the idle TTL expired.
	if r.sessionLimit > 0 && len(r.byClient) >= r.sessionLimit {
		r.mu.Unlock()
		if s.proxyPort != 0 {
			r.portPool.free(s.proxyPort)
		}
		if s.proxyIdent != 0 && s.proxyIdent != 1 {
			r.portPool.free(s.proxyIdent)
		}
		r.denied.Add(1)
		r.st.Drop(1)
		r.st.Error(fmt.Sprintf("raw 会话数达到上限 %d，丢弃来自 %s 的新会话", r.sessionLimit, h.SrcIP()))
		return nil, false
	}
	r.byClient[key] = s
	r.byReply[s.reply] = s
	r.mu.Unlock()
	return s, true
}

// lookupReply finds the session a packet from the target belongs to.
func (r *RawListener) lookupReply(h *netutil.Header, payload []byte) *rawSession {
	key, ok := r.replyLookupKey(h, payload)
	if !ok {
		return nil
	}
	r.mu.RLock()
	sess := r.byReply[key]
	r.mu.RUnlock()
	return sess
}

// clientKey builds the flow identity of a client packet.
func (r *RawListener) clientKey(h *netutil.Header, ident netutil.FlowIdentity, hasIdent bool) clientKey {
	var key clientKey
	copy(key.ip[:], h.Src4())
	if hasIdent && ident.HasPorts {
		key.port = ident.SrcPort
	}
	if hasIdent && ident.HasIdent {
		key.ident = ident.Ident
	}
	return key
}

// replyKeyOf builds the flow identity of the replies to a session.
func (r *RawListener) replyKeyOf(s *rawSession) replyKey {
	var key replyKey
	copy(key.ip[:], s.targetIP.To4())
	key.port = s.proxyPort
	key.ident = s.proxyIdent
	return key
}

// replyLookupKey builds the flow identity a reply from the target is matched on.
// It reports false when the packet carries no field the reply table is keyed by,
// which is the case for a protocol without a port or identifier header.
func (r *RawListener) replyLookupKey(h *netutil.Header, payload []byte) (replyKey, bool) {
	var key replyKey
	copy(key.ip[:], h.Src4())
	if r.portMode() != portsNone {
		_, port, ok := r.readPorts(payload)
		if !ok {
			return replyKey{}, false
		}
		key.port = port // the port we sent *to*
		return key, true
	}
	if ident, ok := netutil.ParseFlow(r.proto, payload); ok && ident.HasIdent {
		key.ident = ident.Ident
	}
	return key, true
}

func (r *RawListener) isProxyPort(h *netutil.Header, payload []byte) bool {
	if r.portMode() != portsNone {
		src, _, ok := r.readPorts(payload)
		if !ok {
			return false
		}
		r.mu.RLock()
		defer r.mu.RUnlock()
		for _, s := range r.byClient {
			if s.proxyPort == src {
				return true
			}
		}
		return false
	}
	if ident, ok := netutil.ParseFlow(r.proto, payload); ok && ident.HasIdent {
		r.mu.RLock()
		defer r.mu.RUnlock()
		for _, s := range r.byClient {
			if s.proxyIdent == ident.Ident {
				return true
			}
		}
	}
	return false
}

func (r *RawListener) reapLoop() {
	defer r.wg.Done()
	interval := r.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.mu.Lock()
			var dead []*rawSession
			for k, s := range r.byClient {
				if s.idle() >= r.ttl {
					delete(r.byClient, k)
					delete(r.byReply, s.reply)
					dead = append(dead, s)
				}
			}
			r.mu.Unlock()
			for _, s := range dead {
				s.closed.Store(true)
				if s.proxyPort != 0 {
					r.portPool.free(s.proxyPort)
				}
				if s.proxyIdent != 0 && s.proxyIdent != 1 {
					r.portPool.free(s.proxyIdent)
				}
				r.st.ConnClosed()
				r.log.Debugf("raw", "session %s closed (%d packets, %d bytes)", s.describe(), s.packets.Load(), s.bytes.Load())
			}
		}
	}
}

// Stop closes both sockets and clears every session.
func (r *RawListener) Stop() {
	r.closeO.Do(func() {
		close(r.done)
		if r.cap != nil {
			_ = r.cap.Close()
		}
		if r.send != nil {
			_ = r.send.Close()
		}
	})
	r.wg.Wait()
	r.mu.Lock()
	count := len(r.byClient)
	r.byClient = map[clientKey]*rawSession{}
	r.byReply = map[replyKey]*rawSession{}
	r.fragments = map[fragmentKey]*rawSession{}
	r.mu.Unlock()
	for i := 0; i < count; i++ {
		r.st.ConnClosed()
	}
}

// Active reports the number of live sessions.
func (r *RawListener) Active() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return int64(len(r.byClient))
}

// Sessions reports the number of tracked flows.
func (r *RawListener) Sessions() int { return int(r.Active()) }

// describe renders a session for the log: who the client is and which
// proxy port/identifier the relay uses towards the target.
func (s *rawSession) describe() string {
	sb := &strings.Builder{}
	sb.WriteString(s.clientIP.String())
	if s.clientPort != 0 {
		fmt.Fprintf(sb, ":%d", s.clientPort)
	} else if s.clientIdent != 0 {
		fmt.Fprintf(sb, " id=%d", s.clientIdent)
	}
	if s.proxyPort != 0 {
		fmt.Fprintf(sb, " (proxy port %d)", s.proxyPort)
	} else if s.proxyIdent != 0 {
		fmt.Fprintf(sb, " (proxy id %d)", s.proxyIdent)
	}
	return sb.String()
}

// portAllocator hands out unique proxy ports/identifiers for raw sessions.
type portAllocator struct {
	mu   sync.Mutex
	next uint16
	low  uint16
	high uint16
	used map[uint16]bool
}

func newPortAllocator(low, high uint16) *portAllocator {
	return &portAllocator{next: low, low: low, high: high, used: map[uint16]bool{}}
}

func (p *portAllocator) alloc() uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := int(p.high) - int(p.low) + 1
	for i := 0; i < total; i++ {
		cur := p.next
		p.next++
		if p.next > p.high {
			p.next = p.low
		}
		if !p.used[cur] {
			p.used[cur] = true
			return cur
		}
	}
	return 0
}

func (p *portAllocator) free(port uint16) {
	if port == 0 {
		return
	}
	p.mu.Lock()
	delete(p.used, port)
	p.mu.Unlock()
}
