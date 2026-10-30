package engine

import (
	"net"
	"os"
	"runtime"
	"testing"
)

// rawTestAddresses returns the client, listen and target addresses used by raw
// socket tests, skipping when they are not configured on this machine.
//
// Linux and OpenBSD treat the whole 127.0.0.0/8 block as local, so the tests work
// there without adding aliases; Windows only owns 127.0.0.1 and its capture path
// ignores loopback, which is why scripts/e2e-aliases.ps1 adds real addresses.
func rawTestAddresses(t *testing.T) (client, listen, target net.IP) {
	t.Helper()
	pick := func(env, fallback string) net.IP {
		v := os.Getenv(env)
		if v == "" {
			v = fallback
		}
		return net.ParseIP(v).To4()
	}
	client = pick("L4FWD_E2E_CLIENT", "172.16.0.40")
	listen = pick("L4FWD_E2E_LISTEN", "172.16.0.32")
	target = pick("L4FWD_E2E_TARGET", "172.16.0.41")
	if runtime.GOOS != "windows" {
		client = pick("L4FWD_E2E_CLIENT", "127.0.0.2")
		listen = pick("L4FWD_E2E_LISTEN", "127.0.0.1")
		target = pick("L4FWD_E2E_TARGET", "127.0.0.3")
	}
	if !isLocalTestIP(listen) || !isLocalTestIP(target) {
		t.Skip("raw socket test addresses are not configured; run scripts/e2e-aliases.ps1 -Add")
	}
	requireRawPrivilege(t)
	return client, listen, target
}

func isLocalTestIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// A loopback address is local without appearing in the interface list on
	// Linux and OpenBSD (the list carries 127.0.0.1/8 as one entry).
	if runtime.GOOS != "windows" && ip.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// requireRawPrivilege skips tests that open raw sockets when the process cannot.
// Linux and OpenBSD need root (or CAP_NET_RAW); the GitHub Linux runner executes
// the test suite through sudo for exactly this reason.
func requireRawPrivilege(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		t.Skip("raw socket tests need root or CAP_NET_RAW")
	}
}
