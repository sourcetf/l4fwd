// Command rawtest is a small harness used to exercise l4fwd's raw IP relay.
//
// It can promiscuously capture IPv4 packets for one protocol (SIO_RCVALL) and
// craft arbitrary IP packets (IP_HDRINCL), which makes it possible to drive a
// relay end to end with a protocol that no stack implements, such as a made up
// protocol number with ports.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const sioRcvAll = 0x98000001

type sa4 struct {
	Family int16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "observe":
		observe(os.Args[2:])
	case "send":
		send(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `rawtest 用法:
  rawtest observe -iface <本机IP> -proto <N> [-seconds 10] [-port N]
      混杂捕获（SIO_RCVALL）指定协议的 IPv4 报文并打印

  rawtest send -src <IP> -dst <IP> -proto <N> [-sport N] [-dport N] [-payload abc] [-id N] [-frag N] [-mf]
      构造并发送一个原始 IPv4 报文 (IP_HDRINCL)`)
}

func observe(args []string) {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	iface := fs.String("iface", "", "绑定捕获的网卡 IP")
	proto := fs.Int("proto", 200, "IP 协议号")
	seconds := fs.Int("seconds", 10, "捕获时长")
	port := fs.Int("port", -1, "只打印目标端口为该值的报文（-1 表示全部）")
	_ = fs.Parse(args)

	ip := net.ParseIP(*iface).To4()
	if ip == nil {
		fatal("observe 需要 -iface 指定具体网卡 IP（SIO_RCVALL 不接受 0.0.0.0）")
	}
	fd, err := windows.WSASocket(int32(windows.AF_INET), int32(windows.SOCK_RAW), int32(*proto), nil, 0, 0)
	if err != nil {
		fatal("socket: " + err.Error())
	}
	defer windows.Closesocket(fd)
	bindSA := &windows.SockaddrInet4{Port: 0, Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]}}
	if err := windows.Bind(fd, bindSA); err != nil {
		fatal("bind: " + err.Error())
	}
	mode := uint32(3) // RCVALL_IPLEVEL
	var out [4]byte
	var ret uint32
	if err := windows.WSAIoctl(fd, sioRcvAll, (*byte)(unsafe.Pointer(&mode)), 4, &out[0], 4, &ret, nil, 0); err != nil {
		fatal("SIO_RCVALL: " + err.Error())
	}
	fmt.Printf("observer: proto=%d iface=%s 时长=%ds\n", *proto, ip, *seconds)

	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(*seconds) * time.Second)
	for time.Now().Before(deadline) {
		var n, flags uint32
		var from windows.RawSockaddrAny
		fl := int32(unsafe.Sizeof(from))
		wb := &windows.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}
		if err := windows.WSARecvFrom(fd, wb, 1, &n, &flags, &from, &fl, nil, nil); err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || int(n) < ihl {
			continue
		}
		src := net.IPv4(buf[12], buf[13], buf[14], buf[15])
		dst := net.IPv4(buf[16], buf[17], buf[18], buf[19])
		payload := buf[ihl:n]
		sport, dport := -1, -1
		if len(payload) >= 4 {
			sport = int(binary.BigEndian.Uint16(payload[0:2]))
			dport = int(binary.BigEndian.Uint16(payload[2:4]))
		}
		if *port >= 0 && dport != *port && sport != *port {
			continue
		}
		frag := ""
		foff := binary.BigEndian.Uint16(buf[6:8]) & 0x1fff
		fl2 := binary.BigEndian.Uint16(buf[6:8]) >> 13
		if foff != 0 || fl2&1 != 0 {
			frag = fmt.Sprintf(" frag(off=%d flags=%d)", foff, fl2)
		}
		body := payload
		if len(body) > 64 {
			body = body[:64]
		}
		portInfo := ""
		if sport >= 0 {
			portInfo = fmt.Sprintf(" sport=%d dport=%d", sport, dport)
		}
		fmt.Printf("PKT %s -> %s proto=%d len=%d%s%s body=%q\n",
			src, dst, buf[9], n, portInfo, frag, body)
	}
}

func send(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	src := fs.String("src", "", "源 IP")
	dst := fs.String("dst", "", "目的 IP")
	proto := fs.Int("proto", 200, "IP 协议号")
	sport := fs.Int("sport", 40000, "源端口（写入载荷前 2 字节）")
	dport := fs.Int("dport", 4000, "目的端口（写入载荷次 2 字节）")
	payload := fs.String("payload", "hello", "载荷文本")
	id := fs.Int("id", 1, "IP 标识")
	frag := fs.Int("frag", 0, "分片偏移（8 字节单位）")
	mf := fs.Bool("mf", false, "设置 MF 标志")
	_ = fs.Parse(args)

	s := net.ParseIP(*src).To4()
	d := net.ParseIP(*dst).To4()
	if s == nil || d == nil {
		fatal("send 需要 -src 与 -dst 的 IPv4 地址")
	}

	fd, err := windows.WSASocket(int32(windows.AF_INET), int32(windows.SOCK_RAW), int32(*proto), nil, 0, 0)
	if err != nil {
		fatal("socket: " + err.Error())
	}
	defer windows.Closesocket(fd)
	if err := windows.SetsockoptInt(fd, windows.IPPROTO_IP, windows.IP_HDRINCL, 1); err != nil {
		fatal("IP_HDRINCL: " + err.Error())
	}
	bindSA := &windows.SockaddrInet4{Port: 0, Addr: [4]byte{s[0], s[1], s[2], s[3]}}
	if err := windows.Bind(fd, bindSA); err != nil {
		fatal("bind: " + err.Error())
	}

	body := make([]byte, 4+len(*payload))
	binary.BigEndian.PutUint16(body[0:2], uint16(*sport))
	binary.BigEndian.PutUint16(body[2:4], uint16(*dport))
	copy(body[4:], *payload)

	flags := uint16(0)
	if *mf {
		flags = 1
	}
	pkt := make([]byte, 20+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], uint16(*id))
	binary.BigEndian.PutUint16(pkt[6:], (flags<<13)|(uint16(*frag)&0x1fff))
	pkt[8] = 64
	pkt[9] = byte(*proto)
	copy(pkt[12:16], s)
	copy(pkt[16:20], d)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:20]))
	copy(pkt[20:], body)

	var rsa windows.RawSockaddrAny
	p := (*sa4)(unsafe.Pointer(&rsa))
	p.Family = windows.AF_INET
	copy(p.Addr[:], d)

	var sent uint32
	wb := &windows.WSABuf{Len: uint32(len(pkt)), Buf: &pkt[0]}
	if err := windows.WSASendTo(fd, wb, 1, &sent, 0, &rsa, int32(unsafe.Sizeof(rsa)), nil, nil); err != nil {
		fatal("WSASendTo: " + err.Error())
	}
	fmt.Printf("sent %s -> %s proto=%d sport=%d dport=%d payload=%q (%d 字节)\n",
		s, d, *proto, *sport, *dport, *payload, sent)
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "rawtest: "+strings.TrimSpace(msg))
	os.Exit(1)
}
