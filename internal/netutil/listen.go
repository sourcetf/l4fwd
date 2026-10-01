package netutil

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// ListenTCP opens a TCP listener for a relay rule.
//
// A wildcard listen address binds dual-stack ("tcp" rather than "tcp4") so IPv6
// clients work. This matters in practice: Windows resolves the name "localhost"
// to ::1 first, and the OpenSSH client shipped with Windows does not fall back to
// 127.0.0.1 when ::1 refuses, so an IPv4-only listener looks like "the forwarder
// is broken" to anyone typing `ssh localhost -p <port>`.
//
// A dual-stack wildcard bind succeeds even when another program already listens
// on 0.0.0.0:port — the two sockets then quietly split the traffic — so the IPv4
// side is probed first and a real conflict is reported instead of accepted.
func ListenTCP(host string, port int) (net.Listener, error) {
	if !IsWildcardHost(host) {
		h := NormalizeHost(host)
		return net.Listen(networkForHost("tcp", h), HostPort(h, port))
	}
	if err := probePortFree("tcp4", port); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", HostPort("", port))
	if err == nil {
		return ln, nil
	}
	// A host without IPv6 must still be able to forward.
	if ipv6Unavailable(err) {
		return net.Listen("tcp4", HostPort("", port))
	}
	return nil, err
}

// ListenUDP opens a UDP socket for a relay rule with the same dual-stack rules as
// ListenTCP.
func ListenUDP(host string, port int) (*net.UDPConn, error) {
	wildcard := IsWildcardHost(host)
	if wildcard {
		if err := probePortFreeUDP("udp4", port); err != nil {
			return nil, err
		}
		// The unspecified IPv6 address with network "udp" is the dual-stack
		// socket: it receives both IPv4 and IPv6 datagrams.
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified, Port: port})
		if err == nil {
			return conn, nil
		}
		if !ipv6Unavailable(err) {
			return nil, err
		}
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	}
	h := NormalizeHost(host)
	network := networkForHost("udp", h)
	laddr, err := net.ResolveUDPAddr(network, HostPort(h, port))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP(laddr.Network(), laddr)
}

// networkForHost picks the family-specific network name for a concrete address.
func networkForHost(prefix, host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return prefix + "6"
	}
	return prefix + "4"
}

// probePortFree verifies the IPv4 side of a port is free before a dual-stack
// bind, so a conflict with another program is reported instead of silently
// sharing the port between two sockets.
func probePortFree(network string, port int) error {
	probe, err := net.Listen(network, HostPort("", port))
	if err != nil {
		if isAddrInUse(err) {
			return fmt.Errorf("端口 %d 已被其它程序占用：%w", port, err)
		}
		return err
	}
	return probe.Close()
}

// probePortFreeUDP is the datagram counterpart of probePortFree: net.Listen only
// accepts stream networks, so the probe has to go through ListenUDP.
func probePortFreeUDP(network string, port int) error {
	ip := net.IPv4zero
	if strings.HasSuffix(network, "6") {
		ip = net.IPv6unspecified
	}
	probe, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		if isAddrInUse(err) {
			return fmt.Errorf("端口 %d 已被其它程序占用：%w", port, err)
		}
		return err
	}
	return probe.Close()
}

// isAddrInUse recognises the "port already bound" error. The Winsock error code
// is not always part of the net package's error chain on Windows, so the message
// is matched as well.
func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errorsAsErrno(err, &errno) && errno == syscall.EADDRINUSE {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"only one usage of each socket address",
		"address already in use",
		"eaddrinuse",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// errorsAsErrno unwraps a syscall.Errno from an error chain.
func errorsAsErrno(err error, target *syscall.Errno) bool {
	for err != nil {
		if e, ok := err.(syscall.Errno); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ipv6Unavailable reports whether an error means "this host has no IPv6".
func ipv6Unavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"address family not supported",
		"protocol not available",
		"eafnosupport",
		"no such device",
		"network is unreachable",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// DialTarget connects to a relay target, preferring IPv4 and falling back to
// IPv6. A forwarder normally sits on an IPv4 path, but a host that only publishes
// an AAAA record must still be reachable.
func DialTarget(host string, port int, timeout time.Duration) (net.Conn, error) {
	host = NormalizeHost(host)
	if ip := net.ParseIP(host); ip != nil {
		network := "tcp4"
		if ip.To4() == nil {
			network = "tcp6"
		}
		d := net.Dialer{Timeout: timeout}
		return d.Dial(network, HostPort(host, port))
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		// Let the resolver error surface with the dialer's own wording.
		d := net.Dialer{Timeout: timeout}
		return d.Dial("tcp", HostPort(host, port))
	}
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	var lastErr error
	for _, group := range [][]net.IP{v4, v6} {
		for _, ip := range group {
			d := net.Dialer{Timeout: timeout}
			conn, derr := d.Dial("tcp", HostPort(ip.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address for %s", host)
	}
	return nil, lastErr
}

// DialTargetUDP opens the upstream socket of a UDP session, with the same
// IPv4-first preference as DialTarget.
func DialTargetUDP(host string, port int) (*net.UDPConn, error) {
	host = NormalizeHost(host)
	target, err := net.ResolveUDPAddr("udp4", HostPort(host, port))
	if err != nil {
		// An AAAA-only host: fall back to IPv6 rather than failing outright.
		target6, err6 := net.ResolveUDPAddr("udp6", HostPort(host, port))
		if err6 != nil {
			return nil, err
		}
		return net.DialUDP("udp6", nil, target6)
	}
	return net.DialUDP("udp4", nil, target)
}
