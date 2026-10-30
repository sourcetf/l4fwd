//go:build !windows

package netutil

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplyConnBuffersSizesAcceptedSocket checks the buffer sizing actually
// reaches a connected socket on Linux and OpenBSD, where accepted connections do
// not inherit the listener's size the way they do on Windows.
func TestApplyConnBuffersSizesAcceptedSocket(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	ApplyConnBuffers(c, 1024)

	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatal("TCP connection does not expose a raw descriptor")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var rcv, snd int
	if err := raw.Control(func(fd uintptr) {
		rcv, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		snd, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	// Linux caps SO_RCVBUF at net.core.rmem_max (208 KiB by default) and reports
	// twice the stored value, so the exact number is not portable. What must hold
	// is that the socket is no longer at the few-tens-of-KiB default.
	if rcv < 128<<10 {
		t.Fatalf("SO_RCVBUF = %d, want at least 128 KiB", rcv)
	}
	if snd < 128<<10 {
		t.Fatalf("SO_SNDBUF = %d, want at least 128 KiB", snd)
	}
}
