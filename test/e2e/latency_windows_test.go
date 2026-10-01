//go:build windows

package e2e

import (
	"fmt"
	"io"
	"net"
	"sort"
	"testing"
	"time"
)

// TestTCPLatencyOverhead measures the round trip latency of a TCP echo server
// with and without l4fwd in the path, for both TCP shapes a rule can have: the
// plain TCP relay and the transparent (gated) one used by TCP-shaped raw rules
// and by "all protocol" rules.
//
// Both configurations terminate the connection in the same kernel stack on the
// same host, so the difference between the two numbers is what the forwarder
// adds to every round trip. The measurement is an average because the Windows
// timer is far coarser than a loopback round trip: single samples read as zero.
func TestTCPLatencyOverhead(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	const samples = 300
	direct := measureEchoLatency(t, "direct", fmt.Sprintf("127.0.0.1:%d", backendPort), samples)

	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	plainPort := freePort(t)
	transPort := freePort(t)
	rules := []map[string]any{
		{
			"kind": "tcp", "listenHost": "127.0.0.1", "listenPort": plainPort,
			"targetHost": "127.0.0.1", "targetPort": backendPort, "enabled": true, "name": "latency-tcp",
		},
		{
			"kind": "raw", "protocol": "tcp", "rawTransport": "transparent",
			"listenHost": "127.0.0.1", "listenPort": transPort,
			"targetHost": "127.0.0.1", "targetPort": backendPort, "enabled": true, "name": "latency-transparent",
		},
	}
	_ = startAgent(t, rules, webAddr)

	plain := measureEchoLatency(t, "plain", fmt.Sprintf("127.0.0.1:%d", plainPort), samples)
	gated := measureEchoLatency(t, "transparent", fmt.Sprintf("127.0.0.1:%d", transPort), samples)

	t.Logf("TCP 回环单字节往返：直连 avg=%v | TCP 转发 avg=%v（+%v）| 透明转发 avg=%v（+%v）",
		direct.avg, plain.avg, plain.avg-direct.avg, gated.avg, gated.avg-direct.avg)
	for label, got := range map[string]latencyStats{"TCP 转发": plain, "透明转发": gated} {
		// A relay on loopback costs microseconds. A millisecond per round trip is a
		// generous ceiling that still catches data being held back (Nagle, a
		// batching timer, a poll interval): those cost tens of milliseconds.
		if got.avg > direct.avg+time.Millisecond {
			t.Fatalf("%s每趟往返多花 %v（直连 %v，经转发 %v）：转发路径上存在人为等待",
				label, got.avg-direct.avg, direct.avg, got.avg)
		}
	}
}

type latencyStats struct {
	avg, p50, p90 time.Duration
}

// measureEchoLatency sends one byte at a time and waits for the echo back, which
// is the same shape as an interactive session (a keystroke, an SSH packet, a
// game datagram) and therefore exposes anything that waits for a full buffer.
func measureEchoLatency(t *testing.T, label, addr string, samples int) latencyStats {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("%s: dial %s: %v", label, addr, err)
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	buf := make([]byte, 1)
	all := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		if _, err := c.Write(buf); err != nil {
			t.Fatalf("%s: write: %v", label, err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("%s: read: %v", label, err)
		}
		if i >= samples/10 { // drop the first tenth as warm up
			all = append(all, time.Since(start))
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	var sum time.Duration
	for _, d := range all {
		sum += d
	}
	return latencyStats{
		avg: sum / time.Duration(len(all)),
		p50: all[len(all)/2],
		p90: all[len(all)*9/10],
	}
}

// TestTCPWriteWriteReadLatency is the Nagle guard.
//
// "write, write, read" is the pattern that Nagle's algorithm punishes: the
// second small write cannot leave while the first is unacknowledged, so the
// peer answers one delayed ACK later — 40 ms on Windows. A forwarder that leaves
// Nagle enabled on either of its two sockets turns every interactive session
// into that pattern, which is what "the latency is much higher than the two legs
// added together" feels like.
func TestTCPWriteWriteReadLatency(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2)
				for {
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	plainPort := freePort(t)
	transPort := freePort(t)
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rules := []map[string]any{
		{
			"kind": "tcp", "listenHost": "127.0.0.1", "listenPort": plainPort,
			"targetHost": "127.0.0.1", "targetPort": backendPort, "enabled": true, "name": "wwr-tcp",
		},
		{
			"kind": "raw", "protocol": "tcp", "rawTransport": "transparent",
			"listenHost": "127.0.0.1", "listenPort": transPort,
			"targetHost": "127.0.0.1", "targetPort": backendPort, "enabled": true, "name": "wwr-transparent",
		},
	}
	_ = startAgent(t, rules, webAddr)

	direct := measureWriteWriteRead(t, fmt.Sprintf("127.0.0.1:%d", backendPort))
	plain := measureWriteWriteRead(t, fmt.Sprintf("127.0.0.1:%d", plainPort))
	gated := measureWriteWriteRead(t, fmt.Sprintf("127.0.0.1:%d", transPort))

	t.Logf("写-写-读平均往返：直连 %v | TCP 转发 %v | 透明转发 %v", direct, plain, gated)
	for label, got := range map[string]time.Duration{"TCP 转发": plain, "透明转发": gated} {
		// Nagle costs a delayed ACK (tens of ms). Anything under a couple of
		// milliseconds means the data left immediately.
		if got > direct+2*time.Millisecond {
			t.Fatalf("%s 的写-写-读往返是 %v（直连 %v）：发送侧被 Nagle 拖住了", label, got, direct)
		}
	}
}

// measureWriteWriteRead times two back-to-back small writes plus the reply.
func measureWriteWriteRead(t *testing.T, addr string) time.Duration {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	const rounds = 40
	buf := make([]byte, 2)
	var sum time.Duration
	count := 0
	for i := 0; i < rounds; i++ {
		start := time.Now()
		if _, err := c.Write([]byte{'a'}); err != nil {
			t.Fatalf("write 1: %v", err)
		}
		if _, err := c.Write([]byte{'b'}); err != nil {
			t.Fatalf("write 2: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if i >= rounds/8 { // skip warm up
			sum += time.Since(start)
			count++
		}
	}
	return sum / time.Duration(count)
}

// TestTCPStreamThroughput asserts the relay does not throttle bulk transfers:
// a copy that is limited by an artificial wait shows up as a low number here
// long before it is visible as latency in an interactive session.
func TestTCPStreamThroughput(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	listenPort := freePort(t)
	rule := map[string]any{
		"kind": "tcp", "listenHost": "127.0.0.1", "listenPort": listenPort,
		"targetHost": "127.0.0.1", "targetPort": backendPort, "enabled": true, "name": "throughput",
	}
	_ = startAgent(t, []map[string]any{rule}, webAddr)

	const total = 32 << 20
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	chunk := make([]byte, 256<<10)
	start := time.Now()
	written := 0
	for written < total {
		n, err := c.Write(chunk)
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
	}
	elapsed := time.Since(start)
	mbps := float64(written) / (1 << 20) / elapsed.Seconds()
	t.Logf("经转发的本机吞吐：%d MiB / %v = %.0f MiB/s", written>>20, elapsed, mbps)
	if mbps < 40 {
		t.Fatalf("吞吐只有 %.0f MiB/s，转发路径在拖慢批量数据", mbps)
	}
}
