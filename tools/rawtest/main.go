// Command rawtest is a small harness used to exercise l4fwd's raw IP relay.
//
// It captures IPv4 packets for one protocol (promiscuously when asked) and
// crafts arbitrary IP packets (IP_HDRINCL), which makes it possible to drive a
// relay end to end with a protocol that no stack implements, such as a made up
// protocol number with ports.
//
// The socket work goes through netutil, so the tool runs on Windows (SIO_RCVALL),
// Linux (AF_PACKET) and OpenBSD (/dev/bpf) alike. Raw sockets need administrator
// rights on all three.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"l4fwd/internal/netutil"
)

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
  rawtest observe -iface <本机IP> -proto <N> [-seconds 10] [-port N] [-sniff]
      捕获指定协议的 IPv4 报文并打印；-sniff 同时抓取非本机地址的报文
      （Windows: SIO_RCVALL；Linux: AF_PACKET；OpenBSD: /dev/bpf）

  rawtest send -src <IP> -dst <IP> -proto <N> [-sport N] [-dport N] [-payload abc] [-id N] [-frag N] [-mf]
      构造并发送一个原始 IPv4 报文 (IP_HDRINCL)`)
}

func observe(args []string) {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	iface := fs.String("iface", "", "绑定捕获的网卡 IP（Windows 混杂捕获必需）")
	proto := fs.Int("proto", 200, "IP 协议号")
	seconds := fs.Int("seconds", 10, "捕获时长")
	port := fs.Int("port", -1, "只打印目标端口为该值的报文（-1 表示全部）")
	sniff := fs.Bool("sniff", false, "同时捕获非本机地址的报文（混杂模式）")
	_ = fs.Parse(args)

	var bindIP net.IP
	if *iface != "" {
		bindIP = net.ParseIP(*iface).To4()
		if bindIP == nil {
			fatal("observe 的 -iface 必须是 IPv4 地址")
		}
	}
	sock, err := netutil.OpenRawSock(netutil.RawSockOptions{
		Proto: *proto, BindIP: bindIP, Sniff: *sniff, RcvBufBytes: 4 << 20,
	})
	if err != nil {
		fatal(err.Error())
	}
	defer sock.Close()
	mode := "本机流量"
	if sock.Sniffing() {
		mode = "混杂捕获"
	}
	fmt.Printf("observer: proto=%d iface=%v 时长=%ds 模式=%s\n", *proto, bindIP, *seconds, mode)

	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(*seconds) * time.Second)
	for time.Now().Before(deadline) {
		ready, err := sock.WaitReadable(200)
		if err != nil {
			fatal("poll: " + err.Error())
		}
		if !ready {
			continue
		}
		pkt, err := sock.ReceivePacket(buf)
		if err != nil {
			if netutil.WouldBlock(err) {
				continue
			}
			fatal("recv: " + err.Error())
		}
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			continue
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			continue
		}
		src := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
		dst := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
		payload := pkt[ihl:]
		sport, dport := -1, -1
		if len(payload) >= 4 {
			sport = int(binary.BigEndian.Uint16(payload[0:2]))
			dport = int(binary.BigEndian.Uint16(payload[2:4]))
		}
		if *port >= 0 && dport != *port && sport != *port {
			continue
		}
		frag := ""
		foff := binary.BigEndian.Uint16(pkt[6:8]) & 0x1fff
		fl := binary.BigEndian.Uint16(pkt[6:8]) >> 13
		if foff != 0 || fl&1 != 0 {
			frag = fmt.Sprintf(" frag(off=%d flags=%d)", foff, fl)
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
			src, dst, pkt[9], len(pkt), portInfo, frag, body)
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

	sock, err := netutil.OpenRawSock(netutil.RawSockOptions{
		Proto: *proto, BindIP: s, HeaderIncl: true, SendOnly: true,
	})
	if err != nil {
		fatal("socket: " + err.Error())
	}
	defer sock.Close()

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

	if err := sock.Send(pkt, d); err != nil {
		fatal("send: " + err.Error())
	}
	fmt.Printf("sent %s -> %s proto=%d sport=%d dport=%d payload=%q (%d 字节)\n",
		s, d, *proto, *sport, *dport, *payload, len(pkt))
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
