package engine

import (
	"net"
	"testing"
)

// TestFreePortIsUsableForBothProtocols pins what freePort promises: the port it
// hands out can be bound for TCP and for UDP.
//
// The Windows port space contains ranges the system reserves for itself (Hyper-V
// and winnat excluded ranges), where a bind fails with WSAEACCES no matter which
// process released the number. A test helper that only probes TCP would hand out
// ports that UDP listeners cannot take, which is how the CI runner failed once:
// "listen udp 127.0.0.1:51891: ... access permissions".
func TestFreePortIsUsableForBothProtocols(t *testing.T) {
	for i := 0; i < 20; i++ {
		port := freePort(t)

		ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
		if err != nil {
			t.Fatalf("第 %d 个端口 %d 无法用于 TCP：%v", i+1, port, err)
		}
		_ = ln.Close()

		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("第 %d 个端口 %d 无法用于 UDP：%v", i+1, port, err)
		}
		_ = pc.Close()
	}
}
