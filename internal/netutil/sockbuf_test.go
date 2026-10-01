//go:build windows

package netutil

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestListenerBuffersAreInherited pins the behaviour the relay's throughput
// depends on: a socket accepted from a sized listener starts with the listener's
// buffers, so no per-connection setsockopt is needed.
//
// It matters because Windows defaults both directions to 64 KiB, and a bulk
// transfer through the relay measured 270 MiB/s at that default against
// 450 MiB/s at 1 MiB on the same link.
func TestListenerBuffersAreInherited(t *testing.T) {
	const wantKB = 1024

	port := freeTCPPort(t)
	gl, err := ListenGated("127.0.0.1", port, wantKB)
	if err != nil {
		t.Fatalf("ListenGated: %v", err)
	}
	defer gl.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		up, _ := net.Listen("tcp4", "127.0.0.1:0")
		defer up.Close()
		go func() {
			c, err := up.Accept()
			if err == nil {
				_ = c.Close()
			}
		}()
		c, err := gl.Accept(func() (net.Conn, error) { return net.Dial("tcp4", up.Addr().String()) })
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.DialTimeout("tcp4", HostPort("127.0.0.1", port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("accept did not return")
	}
	defer server.Close()

	wc, ok := server.(*gatedConn).Conn.(*WinConn)
	if !ok {
		t.Fatalf("accepted connection is %T, want a WinConn", server)
	}
	rcv, err := windows.GetsockoptInt(windows.Handle(wc.fd), windows.SOL_SOCKET, windows.SO_RCVBUF)
	if err != nil {
		t.Fatalf("GetsockoptInt: %v", err)
	}
	snd, err := windows.GetsockoptInt(windows.Handle(wc.fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
	if err != nil {
		t.Fatalf("GetsockoptInt: %v", err)
	}
	t.Logf("被接受的连接：RCVBUF=%d SNDBUF=%d（请求 %d KiB）", rcv, snd, wantKB)
	for name, got := range map[string]int{"SO_RCVBUF": rcv, "SO_SNDBUF": snd} {
		if got < wantKB<<10 {
			t.Errorf("%s = %d，小于请求的 %d：监听套接字上的缓冲没有被子连接继承", name, got, wantKB<<10)
		}
	}
}
