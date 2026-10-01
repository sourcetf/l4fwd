//go:build windows

package netutil

import "golang.org/x/sys/windows"

// setSockbuf sizes both directions of a socket, in KiB.
//
// Both sides are set even though a listener mostly receives: the relay writes to
// the socket it accepted from the listener too, and Windows applies the same
// default to each direction.
func setSockbuf(fd uintptr, kb int) {
	if kb <= 0 {
		return
	}
	_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, kb<<10)
	_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, kb<<10)
}

// SetSockbuf sizes both directions of a connected socket, in KiB. It is exported
// for the transparent path, whose accepted sockets do not come from a listener
// created by this package.
func SetSockbuf(fd uintptr, kb int) { setSockbuf(fd, kb) }
