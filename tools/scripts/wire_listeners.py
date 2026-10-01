#!/usr/bin/env python3
"""Wire the dual-stack listener helper into the three relay listeners."""
import io

edits = [
    (
        "internal/engine/tcp.go",
        """	addr := netutil.HostPort(host, t.rule.ListenPort)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	t.ln = ln
	t.log.Infof("tcp", "listening on %s -> %s:%d (rule %q)", addr, t.rule.TargetHost, t.rule.TargetPort, t.rule.Name)""",
        """	ln, err := netutil.ListenTCP(host, t.rule.ListenPort)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", netutil.HostPort(host, t.rule.ListenPort), err)
	}
	t.ln = ln
	t.log.Infof("tcp", "listening on %s -> %s:%d (rule %q)",
		ln.Addr(), t.rule.TargetHost, t.rule.TargetPort, t.rule.Name)""",
    ),
    (
        "internal/engine/udp.go",
        """	addr := netutil.HostPort(host, u.rule.ListenPort)
	laddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("resolve udp %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", addr, err)
	}
	_ = conn.SetReadBuffer(u.bufSize)
	u.conn = conn
	u.log.Infof("udp", "listening on %s -> %s:%d (rule %q, session ttl %s)", addr, u.rule.TargetHost, u.rule.TargetPort, u.rule.Name, u.ttl)""",
        """	conn, err := netutil.ListenUDP(host, u.rule.ListenPort)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", netutil.HostPort(host, u.rule.ListenPort), err)
	}
	_ = conn.SetReadBuffer(u.bufSize)
	u.conn = conn
	u.log.Infof("udp", "listening on %s -> %s:%d (rule %q, session ttl %s)",
		conn.LocalAddr(), u.rule.TargetHost, u.rule.TargetPort, u.rule.Name, u.ttl)""",
    ),
    (
        "internal/engine/transparent.go",
        """	if !t.gated {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			return fmt.Errorf("listen tcp(transparent) %s: %w", addr, err)
		}
		t.ln = ln
	}""",
        """	if !t.gated {
		ln, err := netutil.ListenTCP(host, t.rule.ListenPort)
		if err != nil {
			return fmt.Errorf("listen tcp(transparent) %s: %w", addr, err)
		}
		t.ln = ln
	}""",
    ),
]

for path, old, new in edits:
    s = io.open(path, encoding="utf-8").read()
    if new.strip().splitlines()[0] in s:
        print(f"{path}: already wired")
        continue
    if s.count(old) != 1:
        print(f"{path}: pattern count {s.count(old)} -- SKIPPED")
        continue
    io.open(path, "w", encoding="utf-8").write(s.replace(old, new))
    print(f"{path}: wired")
