//go:build linux

package netutil

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Promiscuous capture on Linux goes through an AF_PACKET socket: an AF_INET raw
// socket only receives what the IP stack hands to it (traffic addressed to this
// host), while AF_PACKET sees frames on the wire. A classic BPF program attached
// to the socket filters by IP protocol in the kernel, so the process is not woken
// for unrelated traffic — which matters for an "all protocols" rule that opens
// about 250 capture sockets at once.
func openSniffSock(opt RawSockOptions) (*RawSock, error) {
	idx, name, err := pickSniffInterface(opt.BindIP)
	if err != nil {
		return nil, err
	}

	// SOCK_RAW on AF_PACKET keeps the Ethernet header; the protocol argument is
	// the EtherType in network byte order.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("socket(AF_PACKET): %w（混杂捕获需要 root）", err)
		}
		return nil, fmt.Errorf("socket(AF_PACKET): %w", err)
	}
	unix.CloseOnExec(fd)
	rs := &RawSock{
		fd:       fd,
		proto:    opt.Proto,
		kind:     rawKindPacket,
		sniffing: true,
		l2Skip:   14,
		ifName:   name,
	}
	fail := func(e error) (*RawSock, error) {
		_ = unix.Close(fd)
		return nil, e
	}

	// Accept only this IP protocol. The packet socket's protocol already drops
	// non-IPv4 frames; the program looks at the protocol byte inside the IP
	// header (Ethernet header is 14 bytes, protocol is byte 9).
	prog := []unix.SockFilter{
		{Code: 0x30, K: 23}, // BPF_LD|BPF_B|BPF_ABS: A = ip[9]
		{Code: 0x15, Jt: 1, Jf: 0, K: uint32(opt.Proto)}, // JEQ proto
		{Code: 0x06, K: 262144},                          // RET 262144
		{Code: 0x06, K: 0},                               // RET 0
	}
	fprog := &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog); err != nil {
		return fail(fmt.Errorf("SO_ATTACH_FILTER: %w", err))
	}

	if opt.RcvBufBytes > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, opt.RcvBufBytes)
	}

	// Binding to an interface is what makes promiscuous mode meaningful and
	// avoids receiving the same frame once per interface.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  idx,
	}); err != nil {
		return fail(fmt.Errorf("bind AF_PACKET to %s: %w", name, err))
	}
	// Best effort: promiscuous mode needs CAP_NET_ADMIN; without it the socket
	// still sees this host's own traffic, which is the common case anyway.
	_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP,
		&unix.PacketMreq{Ifindex: int32(idx), Type: unix.PACKET_MR_PROMISC})

	if err := unix.SetNonblock(fd, true); err != nil {
		return fail(fmt.Errorf("set non-blocking: %w", err))
	}
	rs.bindIP = opt.BindIP
	return rs, nil
}

// receiveLinkPacket reads one Ethernet frame and returns the IP packet inside.
func (r *RawSock) receiveLinkPacket(buf []byte) ([]byte, error) {
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if isWouldBlockUnix(err) {
				return nil, errWouldBlock
			}
			return nil, err
		}
		if n < r.l2Skip {
			continue
		}
		// The socket is bound to ETH_P_IP, so a well formed frame carries an
		// IPv4 packet right after the 14 byte Ethernet header. Defensive check:
		// a VLAN tag would put the EtherType in another place, and those frames
		// are not delivered by this socket anyway.
		if n < 14 || buf[12] != 0x08 || buf[13] != 0x00 {
			continue
		}
		return buf[r.l2Skip:n], nil
	}
}

// platformPrimaryInterface finds the interface carrying the default route by
// reading /proc/net/route (the first NIC is often a docker bridge).
func platformPrimaryInterface() (int, string, bool) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return 0, "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[1] != "00000000" {
			continue
		}
		ifc, err := net.InterfaceByName(fields[0])
		if err != nil {
			continue
		}
		return ifc.Index, ifc.Name, true
	}
	return 0, "", false
}
