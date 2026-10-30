//go:build windows

package netutil

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// ApplyConnBuffers sizes the kernel send/receive buffers of a connected socket.
//
// On Windows the listener's buffers are inherited by every accepted connection,
// so this is only needed for sockets the relay dials itself (the target side of a
// relay, whose default 64 KiB can limit a fast sender).
func ApplyConnBuffers(c net.Conn, kb int) {
	if c == nil || kb <= 0 {
		return
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, kb<<10)
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, kb<<10)
	})
}
