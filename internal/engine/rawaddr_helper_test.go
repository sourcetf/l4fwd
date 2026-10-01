package engine

import (
	"net"
	"os"
	"testing"
)

// rawTestAddresses returns the listen and target addresses used by raw socket
// tests, skipping when they are not configured on this machine.
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
	if !isLocalTestIP(listen) || !isLocalTestIP(target) {
		t.Skip("raw socket test addresses are not configured; run scripts/e2e-aliases.ps1 -Add")
	}
	return client, listen, target
}

func isLocalTestIP(ip net.IP) bool {
	if ip == nil {
		return false
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
