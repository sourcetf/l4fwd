//go:build linux

package netutil

import "golang.org/x/sys/unix"

// setSockbuf sizes both directions of a socket, in KiB.
//
// Linux caps SO_RCVBUF at net.core.rmem_max (208 KiB by default), which is well
// below the 1 MiB the relay asks for. SO_RCVBUFFORCE bypasses the cap but needs
// CAP_NET_ADMIN; when it is available the forced call is used, and a plain
// setsockopt is the fallback for an unprivileged process. Trying FORCE first
// matters: issuing the plain call afterwards would lower the size back to the
// cap.
func setSockbuf(fd uintptr, kb int) {
	if kb <= 0 {
		return
	}
	bytes := kb << 10
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bytes); err != nil {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, bytes)
	}
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, bytes); err != nil {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, bytes)
	}
}

// SetSockbuf sizes both directions of a connected socket, in KiB.
func SetSockbuf(fd uintptr, kb int) { setSockbuf(fd, kb) }
