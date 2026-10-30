//go:build !windows && !linux && !openbsd

package netutil

import (
	"errors"
	"net"
)

// RawSock is a stub on platforms without a raw socket implementation; the type
// exists so the engine package still compiles there.
type RawSock struct{}

// RawSockOptions mirrors the Windows definition.
type RawSockOptions struct {
	Proto       int
	BindIP      net.IP
	Sniff       bool
	HeaderIncl  bool
	SendOnly    bool
	RcvBufBytes int
	SndBufBytes int
}

// ErrRawUnsupported is returned on platforms without raw socket support here.
var ErrRawUnsupported = errors.New("raw IP sockets are only implemented on Windows in this build")

// OpenRawSock always fails on non-Windows platforms.
func OpenRawSock(RawSockOptions) (*RawSock, error) { return nil, ErrRawUnsupported }

// Proto reports the protocol number.
func (r *RawSock) Proto() int { return 0 }

// BindIP returns the bound address.
func (r *RawSock) BindIP() net.IP { return nil }

// Sniffing reports promiscuous mode.
func (r *RawSock) Sniffing() bool { return false }

// Close is a no-op.
func (r *RawSock) Close() error { return nil }

// Receive is unsupported.
func (r *RawSock) Receive([]byte) (int, error) { return 0, ErrRawUnsupported }

// ReceivePacket is unsupported.
func (r *RawSock) ReceivePacket([]byte) ([]byte, error) { return nil, ErrRawUnsupported }

// Send is unsupported.
func (r *RawSock) Send([]byte, net.IP) error { return ErrRawUnsupported }

// SetNonblocking is unsupported.
func (r *RawSock) SetNonblocking(bool) error { return ErrRawUnsupported }

// WouldBlock is always false here.
func WouldBlock(error) bool { return false }

// RawCaptureLoop is unsupported.
func (r *RawSock) RawCaptureLoop([]byte, <-chan struct{}, func([]byte) error) error {
	return ErrRawUnsupported
}

// FD is unsupported off Windows.
func (r *RawSock) FD() uintptr { return 0 }

// PollOne mirrors the Windows definition.
type PollOne struct {
	FD     uintptr
	Events int16
}

// PollReady is unsupported off Windows.
func PollReady([]PollOne, int) ([]int, error) { return nil, ErrRawUnsupported }
