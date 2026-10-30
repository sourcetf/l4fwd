// Package config defines the persisted configuration schema, validation and
// atomic load/save.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"l4fwd/internal/netutil"
)

// Rule kinds.
const (
	KindTCP = "tcp"
	KindUDP = "udp"
	KindRaw = "raw"
)

// ProtocolAll is the token that expands to "every IP protocol", so a single
// rule can carry traffic the client sends with any protocol number.
const ProtocolAll = "all"

// Config is the root document persisted to disk.
type Config struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
	Settings  Settings  `json:"settings"`
	Rules     []*Rule   `json:"rules"`
	Web       WebConfig `json:"web"`
}

// Settings holds process wide knobs.
type Settings struct {
	LogLevel         string `json:"logLevel"`
	LogToFile        bool   `json:"logToFile"`
	LogFile          string `json:"logFile"`
	DialTimeoutSec   int    `json:"dialTimeoutSec"`
	IdleTimeoutSec   int    `json:"idleTimeoutSec"`
	UDPSessionTTLSec int    `json:"udpSessionTTLSec"`
	BufferKB         int    `json:"bufferKB"`
	// ListenBufferKB sizes the kernel socket buffers of every TCP listener (and,
	// through inheritance, of the connections accepted from them). It is separate
	// from bufferKB because the two answer different questions: bufferKB is the
	// relay's own copy buffer and the basis for the UDP session cap, while this is
	// the amount of data the kernel may hold for a connection the relay has not
	// read yet. Windows defaults to 64 KiB, which caps a bulk transfer well below
	// what the machine can move; see netutil.ListenTCP for the measurements.
	ListenBufferKB int  `json:"listenBufferKB"`
	SamplerMs      int  `json:"samplerMs"`
	StartOnBoot    bool `json:"startOnBoot"`
	AutoStartRules bool `json:"autoStartRules"`
}

// ListenBufferKB returns the socket buffer size for listeners, falling back to a
// size that lets a bulk transfer run at the speed of the slowest hop. Zero in the
// config means "use the default".
func (s Settings) ListenerBufferKB() int {
	if s.ListenBufferKB > 0 {
		return s.ListenBufferKB
	}
	return DefaultListenBufferKB
}

// DefaultListenBufferKB is the listener socket buffer applied when the config does
// not say. 1 MiB is what measured equal to an unbuffered-tuned relay on loopback
// (see netutil.ListenTCP); larger values only help on paths with a long
// bandwidth-delay product, which a forwarder is rarely the bottleneck of.
const DefaultListenBufferKB = 1024

// WebConfig controls the embedded dashboard.
type WebConfig struct {
	Enabled  bool   `json:"enabled"`
	Listen   string `json:"listen"`
	Username string `json:"username"`
	Password string `json:"password"`
	OpenURL  bool   `json:"openBrowser"`
	// AllowedOrigins limits cross-origin access; empty means same-origin only.
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
}

// Rule is one forwarding rule.
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`               // tcp | udp | raw
	Protocol    string   `json:"protocol,omitempty"` // raw only: icmp/gre/esp/... or a number
	ListenHost  string   `json:"listenHost"`         // "" or 0.0.0.0 = all interfaces
	ListenPort  int      `json:"listenPort"`
	TargetHost  string   `json:"targetHost"`
	TargetPort  int      `json:"targetPort"`
	Enabled     bool     `json:"enabled"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	// Tuning (zero values fall back to global settings).
	DialTimeoutSec   int  `json:"dialTimeoutSec,omitempty"`
	IdleTimeoutSec   int  `json:"idleTimeoutSec,omitempty"`
	UDPSessionTTLSec int  `json:"udpSessionTTLSec,omitempty"`
	MaxConns         int  `json:"maxConns,omitempty"`
	PreserveClientIP bool `json:"preserveClientIP,omitempty"` // raw: keep original source IP when possible
	Sniff            bool `json:"sniff,omitempty"`            // raw: promiscuous capture (SIO_RCVALL)
	// PayloadPorts tells the raw relay to treat the first four payload bytes as
	// a source/destination port pair. Bespoke protocols on raw sockets usually
	// carry such a header; without it a rule can only separate clients by IP.
	PayloadPorts bool `json:"payloadPorts,omitempty"`
	// RawTransport selects how a raw rule reads and writes packets. The default
	// ("own") uses its own raw socket on the protocol number, which covers every
	// protocol except TCP. "transparent" lets the kernel stack terminate the
	// traffic so it can be forwarded to a real target port — this is what makes
	// raw/transparent probes and hand crafted TCP conversations forwardable.
	RawTransport string `json:"rawTransport,omitempty"`
	// Gate (transparent only, default true) holds the TCP handshake open until
	// the target accepted, so a connect-only probe learns the target's state.
	Gate     *bool  `json:"gate,omitempty"`
	SourceIP string `json:"sourceIP,omitempty"` // raw: source address for forwarded packets
	TTL      int    `json:"ttl,omitempty"`      // raw: TTL for rewritten packets

	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// Default returns the configuration used when no file exists yet.
func Default() *Config {
	return &Config{
		Version: 1,
		Settings: Settings{
			LogLevel:         "info",
			LogFile:          "l4fwd.log",
			DialTimeoutSec:   10,
			IdleTimeoutSec:   0,
			UDPSessionTTLSec: 60,
			BufferKB:         64,
			SamplerMs:        1000,
		},
		Web: WebConfig{
			Enabled:  true,
			Listen:   "127.0.0.1:8686",
			Username: "admin",
			OpenURL:  true,
		},
		Rules: []*Rule{},
	}
}

// Clone deep copies the config.
func (c *Config) Clone() *Config {
	b, err := json.Marshal(c)
	if err != nil {
		return c
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return c
	}
	return &out
}

// Kinds returns the rule kinds for the UI.
func Kinds() []string { return []string{KindTCP, KindUDP, KindRaw} }

// ProtoTCPNumber is the IP protocol number of TCP, which needs special handling
// because a stateful transport cannot be relayed packet by packet.
const ProtoTCPNumber = 6

// protoNames maps raw protocol keywords to numbers.
var protoNames = map[string]int{
	"icmp": 1, "igmp": 2, "ggp": 3, "ipip": 4, "tcp": 6, "egp": 8,
	"pup": 12, "udp": 17, "hmp": 20, "rdp": 27, "dccp": 33, "gre": 47,
	"esp": 50, "ah": 51, "icmp6": 58, "ospf": 89, "pim": 103,
	"vrrp": 112, "l2tp": 115, "sctp": 132, "udplite": 136, "raw": 255,
	"ospfigp": 89, "rsvp": 46, "ipcomp": 108, "mobility": 135,
}

// ProtocolNumber resolves a raw protocol name or number string. "all" is not a
// protocol number; callers must check IsProtocolAll first.
func ProtocolNumber(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, errors.New("protocol is required for raw rules")
	}
	if s == ProtocolAll {
		return 0, errors.New(`"all" covers every protocol and has no single number`)
	}
	if n, err := netutil.ParsePort(s); err == nil {
		if n == 0 {
			return 0, errors.New("protocol number 0 is not usable")
		}
		return n, nil
	}
	if n, ok := protoNames[s]; ok {
		return n, nil
	}
	if n, err := net.LookupPort("ip", s); err == nil {
		return n, nil
	}
	return 0, fmt.Errorf("unknown IP protocol %q", s)
}

// IsProtocolAll reports whether the rule is meant to carry every IP protocol.
func (r *Rule) IsProtocolAll() bool {
	if r.Kind != KindRaw {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolAll)
}

// ProtocolList returns the individual protocol numbers the rule listens on.
// A normal rule yields one number; an "all" rule yields every number a raw
// socket can serve, which is all of them except:
//
//	0   reserved
//	4   IP-in-IP, 41 IPv6-in-IP: only the outer header is visible, so the relay
//	    could not rewrite the inner packet usefully
//	6   TCP and 17 UDP: TCP needs connection state the relay does not keep, and
//	    plain UDP forwarding is handled by the ordinary TCP/UDP listeners of the
//	    same rule
//	255 IPPROTO_RAW: send-only
func (r *Rule) ProtocolList() ([]int, error) {
	if !r.IsProtocolAll() {
		n, err := ProtocolNumber(r.Protocol)
		if err != nil {
			return nil, err
		}
		return []int{n}, nil
	}
	out := make([]int, 0, 255)
	for n := 1; n <= 254; n++ {
		switch n {
		case ProtoTCPNumber, protoUDPNumber, protoIPv4Tunnel, protoIPv6Tunnel:
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

// Protocol numbers that the "all" expansion leaves to other listeners.
const (
	protoUDPNumber  = 17
	protoIPv4Tunnel = 4
	protoIPv6Tunnel = 41
	protoRawNumber  = 255
)

// AllProtocolCoverage describes, for the UI and the log, how an "all" rule is
// split across listeners.
func AllProtocolCoverage() string {
	return "TCP（透明转发）+ UDP（数据报转发）+ 其余所有 IP 协议（原始套接字）"
}

// ProtocolName returns a human name for a protocol number.
func ProtocolName(n int) string {
	for k, v := range protoNames {
		if v == n && len(k) >= 3 && k != "raw" {
			return strings.ToUpper(k)
		}
	}
	return "IP/" + fmt.Sprint(n)
}

// Raw transport modes for raw rules.
const (
	// RawOwn uses the relay's own raw socket on the rule's protocol number.
	// This covers every protocol except TCP, which needs connection state the
	// relay does not keep (and which Windows refuses to let a raw socket carry at
	// all).
	RawOwn = "own"
	// RawTransparent hands the connection to the kernel stack and forwards it to
	// a real TCP target port. This is what makes hand crafted TCP traffic — a
	// tcping probe, a custom handshake, a non standard TCP client — reach the
	// target address and port, with the target's replies coming back.
	RawTransparent = "transparent"
)

// Transports lists the raw transport modes for the UI.
func Transports() []string { return []string{RawOwn, RawTransparent} }

// IsTCPShaped reports whether the rule targets the TCP protocol itself, which
// cannot be handled by a stateless raw socket relay.
func (r *Rule) IsTCPShaped() bool {
	if r.Kind != KindRaw {
		return false
	}
	if n, err := ProtocolNumber(r.Protocol); err == nil {
		return n == ProtoTCPNumber
	}
	return false
}

// Transport returns the effective raw transport mode, choosing a working
// default for TCP-shaped rules.
func (r *Rule) Transport() string {
	switch r.RawTransport {
	case RawOwn, RawTransparent:
		return r.RawTransport
	}
	if r.IsTCPShaped() {
		// A raw socket cannot carry TCP on Windows, so fall back to the kernel
		// stack, which is what a "reach this target port" rule needs anyway.
		return RawTransparent
	}
	return RawOwn
}

// GateOnTarget reports whether the transparent listener should complete the
// handshake only after the target accepted. Gating makes a connect-only probe
// (a "tcping") report the target's real state instead of the forwarder's, which
// is what such a client is asking about. It can be turned off per rule.
func (r *Rule) GateOnTarget() bool {
	if r.Gate == nil {
		return true
	}
	return *r.Gate
}

// Validate checks the rule and normalises its fields.
func (r *Rule) Validate() error {
	r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
	switch r.Kind {
	case KindTCP, KindUDP, KindRaw:
	default:
		return fmt.Errorf("type must be tcp, udp or raw (got %q)", r.Kind)
	}
	r.ListenHost = netutil.NormalizeHost(r.ListenHost)
	if r.ListenHost != "" {
		if ip := net.ParseIP(r.ListenHost); ip == nil {
			return fmt.Errorf("listen address %q is not a valid IP", r.ListenHost)
		}
		// IPv6 is allowed: a wildcard listen host binds dual-stack, and an explicit
		// IPv6 address is how a rule serves clients that reach it over IPv6.
	}
	if r.Kind == KindRaw && r.ListenHost != "" {
		// The raw relay rewrites IPv4 headers and captures per protocol number, so
		// its listen address has to be an IPv4 address.
		if ip := net.ParseIP(r.ListenHost); ip == nil || ip.To4() == nil {
			return fmt.Errorf("RAW 规则的监听地址必须是 IPv4：%s", r.ListenHost)
		}
	}
	if r.Kind == KindRaw && r.SourceIP != "" {
		if ip := net.ParseIP(r.SourceIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("source IP %q must be IPv4", r.SourceIP)
		}
	}
	if r.ListenPort < 0 || r.ListenPort > 65535 {
		return fmt.Errorf("listen port %d out of range", r.ListenPort)
	}
	if r.Kind != KindRaw && r.ListenPort == 0 {
		return errors.New("listen port is required")
	}
	if strings.TrimSpace(r.TargetHost) == "" {
		return errors.New("target address is required")
	}
	if r.Kind != KindRaw {
		if r.TargetPort <= 0 || r.TargetPort > 65535 {
			return fmt.Errorf("target port %d out of range", r.TargetPort)
		}
	} else {
		r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
		r.RawTransport = strings.ToLower(strings.TrimSpace(r.RawTransport))
		switch r.RawTransport {
		case "", RawOwn, RawTransparent:
		default:
			return fmt.Errorf("raw transport must be own or transparent (got %q)", r.RawTransport)
		}
		if r.IsProtocolAll() {
			// "all" fans out to several listeners: the transparent TCP one owns a
			// real port, so both ports are required. The UDP part reuses the
			// ordinary UDP listener on the same port.
			if r.TargetPort <= 0 {
				return errors.New("协议填 all 时需要填写目标端口（TCP/UDP 部分要用它）")
			}
			if r.ListenPort <= 0 {
				return errors.New("协议填 all 时需要填写监听端口（TCP/UDP 部分要用它）")
			}
			r.RawTransport = RawTransparent // TCP half of "all" goes through the stack
		} else {
			n, err := ProtocolNumber(r.Protocol)
			if err != nil {
				return err
			}
			// The transparent mode owns a real local port and needs a target port,
			// because the kernel stack terminates the transport for both sides.
			if r.Transport() == RawTransparent {
				if r.TargetPort <= 0 {
					return errors.New("transparent 模式需要填写目标端口")
				}
				if r.ListenPort <= 0 {
					return errors.New("transparent 模式需要填写监听端口")
				}
			}
			if n == ProtoTCPNumber && r.RawTransport == RawOwn {
				return errors.New("原始套接字无法承载有状态 TCP：请把转发方式改为 transparent（TCP 透明转发），或把协议填 all")
			}
			if n == protoRawNumber && r.RawTransport == RawOwn {
				return errors.New("协议号 255（IPPROTO_RAW）只能发包不能收包，请改用 all 或具体协议号")
			}
		}
	}
	if r.SourceIP != "" {
		if ip := net.ParseIP(r.SourceIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("source IP %q must be IPv4", r.SourceIP)
		}
	}
	if r.TTL < 0 || r.TTL > 255 {
		return fmt.Errorf("TTL %d out of range", r.TTL)
	}
	if r.Name == "" {
		r.Name = r.Summary()
	}
	return nil
}

// Summary renders a short human description of the rule.
func (r *Rule) Summary() string {
	lh := r.ListenHost
	if lh == "" {
		lh = "0.0.0.0"
	}
	switch r.Kind {
	case KindRaw:
		if r.IsProtocolAll() {
			return fmt.Sprintf("全协议 %s:%d -> %s:%d（TCP+UDP+其余 IP 协议）", lh, r.ListenPort, r.TargetHost, r.TargetPort)
		}
		if r.Transport() == RawTransparent {
			return fmt.Sprintf("TCP透明转发 %s:%d -> %s:%d", lh, r.ListenPort, r.TargetHost, orPort(r.TargetPort))
		}
		return fmt.Sprintf("RAW/%s %s -> %s:%d", strings.ToUpper(r.Protocol), lh, r.TargetHost, orPort(r.TargetPort))
	default:
		return fmt.Sprintf("%s %s:%d -> %s:%d", strings.ToUpper(r.Kind), lh, r.ListenPort, r.TargetHost, r.TargetPort)
	}
}

func orPort(p int) int {
	if p == 0 {
		return 0
	}
	return p
}

// Key returns a stable identity for the primary listener a rule occupies.
// An "all" rule also binds UDP on the same port; Keys() reports every socket it
// holds so conflict detection covers them all.
func (r *Rule) Key() string {
	keys := r.Keys()
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

// Keys lists every listener key the rule occupies. Most rules hold exactly one;
// an "all" rule holds a TCP one, a UDP one and one raw socket per protocol.
func (r *Rule) Keys() []string {
	host := listenKey(r.ListenHost)
	switch r.Kind {
	case KindRaw:
		if r.IsProtocolAll() {
			keys := []string{
				fmt.Sprintf("tcp/%s/%d", host, r.ListenPort),
				fmt.Sprintf("udp/%s/%d", host, r.ListenPort),
				fmt.Sprintf("raw-all/%s", host),
			}
			return keys
		}
		// Transparent mode owns a real TCP port, so key it like a TCP listener.
		if r.Transport() == RawTransparent {
			return []string{fmt.Sprintf("tcp/%s/%d", host, r.ListenPort)}
		}
		n, _ := ProtocolNumber(r.Protocol)
		return []string{fmt.Sprintf("raw/%d/%s", n, host)}
	default:
		return []string{fmt.Sprintf("%s/%s/%d", r.Kind, host, r.ListenPort)}
	}
}

func listenKey(host string) string {
	if netutil.IsWildcardHost(host) {
		return "0.0.0.0"
	}
	return host
}

// DialTimeout returns the effective dial timeout.
func (r *Rule) DialTimeout(g Settings) time.Duration {
	s := r.DialTimeoutSec
	if s <= 0 {
		s = g.DialTimeoutSec
	}
	if s <= 0 {
		s = 10
	}
	return time.Duration(s) * time.Second
}

// IdleTimeout returns the effective idle timeout (0 = unlimited).
func (r *Rule) IdleTimeout(g Settings) time.Duration {
	s := r.IdleTimeoutSec
	if s <= 0 {
		s = g.IdleTimeoutSec
	}
	if s <= 0 {
		return 0
	}
	return time.Duration(s) * time.Second
}

// UDPSessionTTL returns the effective UDP session idle timeout.
func (r *Rule) UDPSessionTTL(g Settings) time.Duration {
	s := r.UDPSessionTTLSec
	if s <= 0 {
		s = g.UDPSessionTTLSec
	}
	if s <= 0 {
		s = 60
	}
	return time.Duration(s) * time.Second
}

// Store wraps a config file with atomic save and change notification.
type Store struct {
	mu       sync.RWMutex
	path     string
	cfg      *Config
	onChange []func(*Config)
}

// NewStore loads the config from path, creating a default file if missing.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.Load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the config file location.
func (s *Store) Path() string { return s.path }

// Load reads the file from disk (or writes defaults when absent).
func (s *Store) Load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		s.mu.Lock()
		s.cfg = Default()
		s.mu.Unlock()
		return s.Save()
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	base := Default()
	if cfg.Version == 0 {
		cfg.Version = base.Version
	}
	mergeSettings(&cfg.Settings, base.Settings)
	if cfg.Web.Listen == "" {
		cfg.Web.Listen = base.Web.Listen
	}
	if cfg.Web.Username == "" {
		cfg.Web.Username = base.Web.Username
	}
	for _, r := range cfg.Rules {
		if r.ID == "" {
			r.ID = NewID()
		}
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	s.mu.Lock()
	s.cfg = &cfg
	s.mu.Unlock()
	return nil
}

func mergeSettings(dst *Settings, def Settings) {
	if dst.LogLevel == "" {
		dst.LogLevel = def.LogLevel
	}
	if dst.LogFile == "" {
		dst.LogFile = def.LogFile
	}
	if dst.DialTimeoutSec <= 0 {
		dst.DialTimeoutSec = def.DialTimeoutSec
	}
	if dst.UDPSessionTTLSec <= 0 {
		dst.UDPSessionTTLSec = def.UDPSessionTTLSec
	}
	if dst.BufferKB <= 0 {
		dst.BufferKB = def.BufferKB
	}
	if dst.SamplerMs <= 0 {
		dst.SamplerMs = def.SamplerMs
	}
}

// Get returns a deep copy of the current configuration.
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Clone()
}

// OnChange registers a callback fired after every successful Save.
func (s *Store) OnChange(fn func(*Config)) {
	s.mu.Lock()
	s.onChange = append(s.onChange, fn)
	s.mu.Unlock()
}

// Save atomically writes cfg to disk and notifies listeners.
func (s *Store) Save() error {
	s.mu.Lock()
	if s.cfg.UpdatedAt.IsZero() || true {
		s.cfg.UpdatedAt = time.Now()
	}
	cfg := s.cfg.Clone()
	var subs []func(*Config)
	subs = append(subs, s.onChange...)
	path := s.path
	s.mu.Unlock()
	return writeAtomic(path, cfg, subs)
}

// Update mutates the config in place under the store lock and persists it.
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.cfg); err != nil {
		return err
	}
	s.cfg.UpdatedAt = time.Now()
	cfg := s.cfg.Clone()
	var subs []func(*Config)
	subs = append(subs, s.onChange...)
	return writeAtomic(s.path, cfg, subs)
}

func writeAtomic(path string, cfg *Config, subs []func(*Config)) error {
	err := func() error {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}()
	if err != nil {
		return err
	}
	for _, fn := range subs {
		fn(cfg)
	}
	return nil
}

// RuleByID returns a copy of the rule with the given id.
func (s *Store) RuleByID(id string) (*Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.cfg.Rules {
		if r.ID == id {
			cp := *r
			return &cp, true
		}
	}
	return nil, false
}

// UpsertRule inserts or replaces a rule (matched by ID) and saves.
func (s *Store) UpsertRule(r *Rule) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	if err := r.Validate(); err != nil {
		return err
	}
	now := time.Now()
	return s.Update(func(c *Config) error {
		for i, ex := range c.Rules {
			if ex.ID == r.ID {
				if r.CreatedAt.IsZero() {
					r.CreatedAt = ex.CreatedAt
				}
				r.UpdatedAt = now
				// Detect duplicate listener keys left behind by the edit; every
				// key the rule holds is checked, not just the primary one.
				for j, other := range c.Rules {
					if j == i {
						continue
					}
					if key, clash := sharedKey(r, other); clash {
						return fmt.Errorf("rule %q already listens on %s", other.Name, key)
					}
				}
				c.Rules[i] = r
				return nil
			}
		}
		if r.CreatedAt.IsZero() {
			r.CreatedAt = now
		}
		r.UpdatedAt = now
		for _, other := range c.Rules {
			if key, clash := sharedKey(r, other); clash {
				return fmt.Errorf("rule %q already listens on %s", other.Name, key)
			}
		}
		c.Rules = append(c.Rules, r)
		return nil
	})
}

// sharedKey reports the first listener key two rules would fight over.
func sharedKey(a, b *Rule) (string, bool) {
	// A whole-net rule ("all") is keyed by "raw-all/<host>" because it owns every
	// protocol number; a rule for a single protocol number only clashes with it
	// when both want the same host.
	for _, ka := range a.Keys() {
		for _, kb := range b.Keys() {
			if ka == kb {
				return ka, true
			}
			allA := strings.HasPrefix(ka, "raw-all/")
			allB := strings.HasPrefix(kb, "raw-all/")
			switch {
			case allA && strings.HasPrefix(kb, "raw/"):
				return kb, true // "all" already carries that protocol number
			case allB && strings.HasPrefix(ka, "raw/"):
				return ka, true
			}
		}
	}
	return "", false
}

// DeleteRule removes a rule by id and saves.
func (s *Store) DeleteRule(id string) error {
	return s.Update(func(c *Config) error {
		out := c.Rules[:0]
		found := false
		for _, r := range c.Rules {
			if r.ID == id {
				found = true
				continue
			}
			out = append(out, r)
		}
		if !found {
			return fmt.Errorf("rule %s not found", id)
		}
		c.Rules = out
		return nil
	})
}

// SetRuleEnabled toggles the enabled flag of one rule.
func (s *Store) SetRuleEnabled(id string, enabled bool) error {
	return s.Update(func(c *Config) error {
		for _, r := range c.Rules {
			if r.ID == id {
				r.Enabled = enabled
				r.UpdatedAt = time.Now()
				return nil
			}
		}
		return fmt.Errorf("rule %s not found", id)
	})
}

// SortedRules returns rules ordered by kind then listen port for display.
func (c *Config) SortedRules() []*Rule {
	out := append([]*Rule(nil), c.Rules...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].ListenPort != out[j].ListenPort {
			return out[i].ListenPort < out[j].ListenPort
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Session budget defaults shared by the listeners. They live here so an
// "all protocol" rule can divide one budget among its parts instead of letting
// every protocol number inherit a full one.
const (
	// UDPSessionBudgetBytes is the memory the per-session receive buffers of one
	// rule may occupy when maxConns is not set.
	UDPSessionBudgetBytes = 64 << 20
	// UDPSessionMinSessions keeps the automatic cap usable for ordinary traffic.
	UDPSessionMinSessions = 256
	// UDPSessionMaxCeiling bounds an explicit maxConns.
	UDPSessionMaxCeiling = 65536
	// RawSessionBudget is the automatic session cap of a raw rule.
	RawSessionBudget = 4096
	// RawSessionMaxCeiling bounds an explicit maxConns on a raw rule.
	RawSessionMaxCeiling = 16384
)

// AllProtocolSessionShare divides a rule's session budget among the listeners of
// an "all protocol" rule, so the rule as a whole honours maxConns (or the
// automatic budget) instead of multiplying it by the number of protocol numbers.
func AllProtocolSessionShare(rule *Rule, parts int) int {
	if parts < 1 {
		parts = 1
	}
	budget := RawSessionBudget
	if rule != nil && rule.MaxConns > 0 {
		budget = rule.MaxConns
	}
	share := budget / parts
	if share < 8 {
		// Below this a part would refuse legitimate traffic; keep a floor and let
		// the per-part caps bound the total instead.
		share = 8
	}
	return share
}
