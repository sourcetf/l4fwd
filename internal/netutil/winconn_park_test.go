//go:build windows

package netutil

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestWinConnReadParksInsteadOfSpinning guards the property that made an idle
// forwarded connection burn a full core: WinConn's socket is non-blocking, so a
// read with no data available must wait for readability instead of retrying
// WSARecv in a loop.
//
// The test issues a read on a fresh connection and asserts it stays parked until
// the peer writes. A spinning read would still be "parked" in this sense, so the
// caller side is paired with TestTransparentIdleConnectionDoesNotSpin, which
// measures the process's own CPU time.
func TestWinConnReadParksInsteadOfSpinning(t *testing.T) {
	gl, upstreamLn, port := gatedPair(t)
	defer gl.Close()
	defer upstreamLn.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := gl.Accept(func() (net.Conn, error) { return net.Dial("tcp4", upstreamLn.Addr().String()) })
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	client, err := net.DialTimeout("tcp4", HostPort("127.0.0.1", port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("accept did not return")
	}
	defer server.Close()

	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}

	done := make(chan int, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := server.Read(buf)
		done <- n
	}()

	select {
	case n := <-done:
		t.Fatalf("read returned %d bytes although the peer wrote nothing: the read is not parked", n)
	case <-time.After(400 * time.Millisecond):
	}

	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	select {
	case n := <-done:
		if n != 2 {
			t.Fatalf("read returned %d bytes, want 2", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read did not return after the peer wrote")
	}
}

// gatedPair opens a gated listener plus the target listener its gate dials.
func gatedPair(t *testing.T) (*GatedListener, net.Listener, int) {
	t.Helper()
	upstreamLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listener: %v", err)
	}
	// The gate dial must not block the accept path, so the upstream accepts in
	// the background.
	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) }(c)
		}
	}()
	port := freeTCPPort(t)
	gl, err := ListenGated("127.0.0.1", port, 0)
	if err != nil {
		upstreamLn.Close()
		t.Fatalf("ListenGated: %v", err)
	}
	return gl, upstreamLn, port
}

// TestWinConnEnablesNoDelay checks the relay's own socket wrapper disables Nagle.
// A relay holds no data back: leaving Nagle on delays a small write until the
// previous one is acknowledged, which is exactly the latency an interactive
// session feels.
func TestWinConnEnablesNoDelay(t *testing.T) {
	gl, upstreamLn, port := gatedPair(t)
	defer gl.Close()
	defer upstreamLn.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := gl.Accept(func() (net.Conn, error) { return net.Dial("tcp4", upstreamLn.Addr().String()) })
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.DialTimeout("tcp4", HostPort("127.0.0.1", port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("accept did not return")
	}
	defer server.Close()

	wc, ok := server.(*gatedConn).Conn.(*WinConn)
	if !ok {
		t.Fatalf("the gated listener handed out %T, want a *WinConn inside", server)
	}
	if !wc.NoDelayEnabled() {
		t.Fatal("the relay's socket wrapper left Nagle enabled on the accepted connection")
	}
}
