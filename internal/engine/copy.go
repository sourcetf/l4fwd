// Package engine implements the actual forwarding: TCP stream relay, UDP
// datagram relay and IP protocol (raw socket) relay, plus the rule manager
// that keeps running listeners in sync with the configuration.
package engine

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"l4fwd/internal/netutil"
	"l4fwd/internal/stats"
)

// defaultBufferSize matches the largest useful socket read and keeps
// allocations out of the hot path.
const defaultBufferSize = 64 * 1024

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, defaultBufferSize)
		return &b
	},
}

func getBuffer() *[]byte  { return bufferPool.Get().(*[]byte) }
func putBuffer(b *[]byte) { bufferPool.Put(b) }

// tuneTCP applies the options every relayed connection needs: Nagle off (a relay
// must never hold a small write back), keepalive on (an abandoned connection is
// reaped by the kernel), and kernel buffers sized so a bulk transfer is not
// limited by the platform default.
//
// The tuning is interface based rather than a *net.TCPConn assertion because the
// gated listener wraps accepted sockets in its own connection type.
func tuneTCP(c net.Conn, bufferKB int) {
	if c == nil {
		return
	}
	type tuner interface {
		SetNoDelay(bool) error
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}
	if t, ok := c.(tuner); ok {
		_ = t.SetNoDelay(true)
		_ = t.SetKeepAlive(true)
		_ = t.SetKeepAlivePeriod(30 * time.Second)
	}
	netutil.ApplyConnBuffers(c, bufferKB)
}

// halfCloser is implemented by *net.TCPConn.
type halfCloser interface {
	CloseWrite() error
}

// closeWrite closes only the write side when possible, otherwise the whole
// connection. This propagates EOF without tearing down the reverse direction.
func closeWrite(c net.Conn) {
	if c == nil {
		return
	}
	if hc, ok := c.(halfCloser); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = c.Close()
}

// pipeOneWay copies src to dst until EOF or an idle timeout, then half closes
// dst. dir says whether the bytes flow towards the target (DirIn) or back to
// the client (DirOut) so statistics stay meaningful.
func pipeOneWay(dst, src net.Conn, idle time.Duration, ctr *stats.RuleStats, dir stats.Direction) (int64, error) {
	bufp := getBuffer()
	defer putBuffer(bufp)
	buf := *bufp

	var total int64
	var err error
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		var n int
		n, err = src.Read(buf)
		if n > 0 {
			total += int64(n)
			if ctr != nil {
				// Each read is one segment (or a burst of them) on the wire, which
				// is what the dashboard's "包" column counts.
				ctr.RecordPacket(dir, int64(n), true)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				err = werr
				break
			}
		}
		if err != nil {
			break
		}
	}
	closeWrite(dst)
	if err == io.EOF {
		err = nil
	}
	return total, err
}

// relayPair copies in both directions and closes both sides when finished.
func relayPair(a, b net.Conn, idle time.Duration, ctr *stats.RuleStats) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := pipeOneWay(b, a, idle, ctr, stats.DirIn); err != nil && ctr != nil {
			ctr.Error("client to target: " + err.Error())
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := pipeOneWay(a, b, idle, ctr, stats.DirOut); err != nil && ctr != nil {
			ctr.Error("target to client: " + err.Error())
		}
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// drainAndClose reads and discards whatever the peer already sent before
// closing, so Windows sends a FIN instead of an RST. Without this a client
// that pipelined a request into a failed forward sees "connection reset".
func drainAndClose(c net.Conn, budget time.Duration) {
	if c == nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(budget))
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	closeWrite(c)
	_ = c.Close()
}

// benignErr reports errors that only mean "the peer went away", which happen
// on every normal connection close and should not fill the log or error count.
func benignErr(err error) bool {
	if err == nil || err == io.EOF {
		return true
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	if opErr.Timeout() {
		return true
	}
	s := strings.ToLower(opErr.Error())
	for _, sub := range []string{
		"use of closed network connection",
		"forcibly closed",
		"connection reset",
		"connection abort",
		"broken pipe",
		"wsarecv",
		"wsasend",
		"the specified network name is no longer available",
	} {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
