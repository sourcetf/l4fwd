//go:build openbsd

package netutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Promiscuous capture on OpenBSD goes through /dev/bpf. An AF_INET raw socket
// only sees traffic delivered to this host; BPF sees the wire. The device is put
// in immediate mode and non-blocking, and a small classic-BPF program keeps
// non-IPv4 frames out of the read path.
//
// bpf_hdr (OpenBSD, 64 bit) is 28 bytes, but only the fields the relay needs are
// read: bh_caplen at offset 8, bh_hdrlen at offset 16. bh_hdrlen is the offset of
// the packet inside the record, so it is used instead of assuming the struct
// size. BPF_ALIGNMENT is sizeof(u_int32_t) on OpenBSD, so records are padded to
// four bytes.
const (
	bpfHdrMin = 28
	// bpfBufSize is the capture buffer requested from the kernel. It is also the
	// read size, so a burst is read in one syscall.
	bpfBufSize = 1 << 20
)

// DLT values the code understands.
const (
	dltNull   = 0  // 4 byte family in host order
	dltEn10mb = 1  // Ethernet
	dltLoop   = 12 // 4 byte family in network order (OpenBSD loopback)
	afInet    = 2  // AF_INET on OpenBSD
)

type bpfInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type bpfProgram struct {
	Len   uint32
	_     uint32
	Insns uintptr
}

func openSniffSock(opt RawSockOptions) (*RawSock, error) {
	idx, name, err := pickSniffInterface(opt.BindIP)
	if err != nil {
		return nil, err
	}
	_ = idx

	fd, err := openBPFDevice()
	if err != nil {
		return nil, err
	}
	rs := &RawSock{
		fd:       fd,
		proto:    opt.Proto,
		kind:     rawKindBPF,
		sniffing: true,
		ifName:   name,
	}
	fail := func(e error) (*RawSock, error) {
		_ = unix.Close(fd)
		return nil, e
	}

	// The buffer size has to be set before the interface is attached.
	if err := unix.IoctlSetInt(fd, unix.BIOCSBLEN, bpfBufSize); err != nil {
		return fail(fmt.Errorf("/dev/bpf BIOCSBLEN: %w", err))
	}
	if err := setBPFInterface(fd, name); err != nil {
		return fail(err)
	}
	// One read per packet group; without immediate mode the kernel holds data
	// until its buffer is full, which would make a forwarded packet wait.
	if err := unix.IoctlSetInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fail(fmt.Errorf("/dev/bpf BIOCIMMEDIATE: %w", err))
	}
	// Promiscuous mode is best effort: on a loopback interface it is refused,
	// and capturing only this host's traffic is still useful.
	_ = ioctl(fd, unix.BIOCPROMISC, 0)

	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return fail(fmt.Errorf("/dev/bpf BIOCGDLT: %w", err))
	}
	switch dlt {
	case dltEn10mb:
		rs.l2Skip = 14
		if err := setBPFFilter(fd, 12, 0x0800); err != nil {
			return fail(err)
		}
	case dltNull, dltLoop:
		rs.l2Skip = 4
		// The loopback family field is in host order for DLT_NULL and network
		// order for DLT_LOOP; both are accepted by the relay's IPv4 check, so no
		// kernel filter is attached (loopback traffic is small anyway).
	default:
		return fail(fmt.Errorf("不支持的 BPF 链路类型 %d（接口 %s）", dlt, name))
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		return fail(fmt.Errorf("set non-blocking: %w", err))
	}
	if opt.RcvBufBytes > 0 {
		// BPF has its own buffer; the socket option is harmless.
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, opt.RcvBufBytes)
	}
	rs.bindIP = opt.BindIP
	return rs, nil
}

// openBPFDevice claims one of the clone devices; each open gets a free unit.
func openBPFDevice() (int, error) {
	var lastErr error
	for i := 0; i < 256; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR, 0)
		if err == nil {
			unix.CloseOnExec(fd)
			return fd, nil
		}
		if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
			lastErr = err
			continue
		}
		if errors.Is(err, unix.ENOENT) {
			lastErr = err
			continue
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no /dev/bpf unit available")
	}
	return -1, fmt.Errorf("open /dev/bpf: %w（混杂捕获需要 root，且内核需启用 bpf）", lastErr)
}

// setBPFInterface attaches the capture to one interface.
func setBPFInterface(fd int, name string) error {
	// struct ifreq is 32 bytes on OpenBSD; only the name field is used.
	var req [32]byte
	if len(name) >= 16 {
		return fmt.Errorf("interface name %q too long", name)
	}
	copy(req[:16], name)
	if err := ioctl(fd, unix.BIOCSETIF, uintptr(unsafe.Pointer(&req[0]))); err != nil {
		return fmt.Errorf("/dev/bpf BIOCSETIF %s: %w", name, err)
	}
	return nil
}

// setBPFFilter accepts frames whose 16 bit value at offset matches want.
func setBPFFilter(fd int, offset int, want uint32) error {
	prog := []bpfInsn{
		{Code: 0x28, K: uint32(offset)}, // BPF_LD|BPF_H|BPF_ABS
		{Code: 0x15, Jt: 1, Jf: 0, K: want},
		{Code: 0x06, K: bpfBufSize},
		{Code: 0x06, K: 0},
	}
	p := bpfProgram{Len: uint32(len(prog)), Insns: uintptr(unsafe.Pointer(&prog[0]))}
	if err := ioctl(fd, unix.BIOCSETF, uintptr(unsafe.Pointer(&p))); err != nil {
		return fmt.Errorf("/dev/bpf BIOCSETF: %w", err)
	}
	return nil
}

// ioctl performs one ioctl on the BPF device.
func ioctl(fd int, req uintptr, arg uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

// receiveLinkPacket returns the next IPv4 packet from a BPF record.
func (r *RawSock) receiveLinkPacket(buf []byte) ([]byte, error) {
	for {
		if len(r.bpfPending) >= bpfHdrMin {
			caplen := int(binary.LittleEndian.Uint32(r.bpfPending[8:12]))
			hdrlen := int(binary.LittleEndian.Uint16(r.bpfPending[16:18]))
			if hdrlen < bpfHdrMin || hdrlen > len(r.bpfPending) {
				r.bpfPending = nil
				continue
			}
			end := hdrlen + caplen
			if end > len(r.bpfPending) {
				end = len(r.bpfPending)
				caplen = end - hdrlen
			}
			pkt := r.bpfPending[hdrlen:end]
			// Advance to the next record, padded to BPF_ALIGNMENT (4).
			adv := (end + 3) &^ 3
			if adv <= 0 || adv > len(r.bpfPending) {
				adv = len(r.bpfPending)
			}
			r.bpfPending = r.bpfPending[adv:]
			ip, ok := stripLinkHeader(pkt)
			if !ok {
				continue
			}
			return append(buf[:0], ip...), nil
		}
		if r.bpfBuf == nil {
			r.bpfBuf = make([]byte, bpfBufSize)
		}
		for {
			n, err := unix.Read(r.fd, r.bpfBuf)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				if isWouldBlockUnix(err) {
					return nil, errWouldBlock
				}
				return nil, err
			}
			if n <= 0 {
				return nil, errWouldBlock
			}
			r.bpfPending = r.bpfBuf[:n]
			break
		}
	}
}

// stripLinkHeader removes the DLT specific header and checks that an IPv4 packet
// follows.
func stripLinkHeader(pkt []byte) ([]byte, bool) {
	if len(pkt) < 4 {
		return nil, false
	}
	switch {
	case len(pkt) >= 14 && pkt[12] == 0x08 && pkt[13] == 0x00:
		return pkt[14:], len(pkt) > 14
	case binary.LittleEndian.Uint32(pkt[:4]) == afInet:
		return pkt[4:], len(pkt) > 4
	case binary.BigEndian.Uint32(pkt[:4]) == afInet:
		return pkt[4:], len(pkt) > 4
	}
	return nil, false
}

// platformPrimaryInterface picks the first non-loopback interface with an IPv4
// address. OpenBSD hosts are usually routers with one uplink, so this is enough.
func platformPrimaryInterface() (int, string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, "", false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			var got net.IP
			switch v := a.(type) {
			case *net.IPNet:
				got = v.IP
			case *net.IPAddr:
				got = v.IP
			}
			if got != nil && got.To4() != nil {
				return ifc.Index, ifc.Name, true
			}
		}
	}
	return 0, "", false
}
