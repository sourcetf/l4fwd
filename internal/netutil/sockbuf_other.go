//go:build !windows

package netutil

import "syscall"

// setSockbuf sizes both directions of a socket, in KiB. Off Windows the Go
// runtime owns the socket file descriptor, so this is a plain setsockopt.
func setSockbuf(fd uintptr, kb int) {
	if kb <= 0 {
		return
	}
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, kb<<10)
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, kb<<10)
}

// SetSockbuf sizes both directions of a connected socket, in KiB.
func SetSockbuf(fd uintptr, kb int) { setSockbuf(fd, kb) }
