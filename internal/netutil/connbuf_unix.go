//go:build !windows

package netutil

import (
	"net"
	"syscall"
)

// ApplyConnBuffers sizes the kernel send/receive buffers of a connected socket.
//
// Windows inherits the listener's buffers on accept, but Linux and OpenBSD do
// not: every accepted connection starts from the system default (a few hundred
// KiB at most on Linux, 16-32 KiB on OpenBSD). Applying the same size here is what
// keeps a bulk transfer through the relay from being window limited.
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
	_ = raw.Control(func(fd uintptr) { setSockbuf(fd, kb) })
}
