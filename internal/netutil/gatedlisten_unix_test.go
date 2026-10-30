//go:build !windows

package netutil

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestGatedListenerDeliversUpstream checks the portable gate runs before the
// connection is handed to the caller and carries the connection it opened.
func TestGatedListenerDeliversUpstream(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	ln, err := ListenGated("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatalf("ListenGated: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	gated := make(chan struct {
		c   net.Conn
		err error
	}, 1)
	go func() {
		c, err := ln.Accept(func() (net.Conn, error) {
			return DialTarget("127.0.0.1", backend.Addr().(*net.TCPAddr).Port, time.Second)
		})
		gated <- struct {
			c   net.Conn
			err error
		}{c, err}
	}()

	client, err := net.DialTimeout("tcp4", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	res := <-gated
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	defer res.c.Close()
	if UpstreamOf(res.c) == nil {
		t.Fatal("the gate's upstream connection was not attached")
	}
	// The accepted connection must be usable through the wrapper.
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 2)
	_ = res.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(res.c, buf); err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if string(buf) != "hi" {
		t.Fatalf("payload = %q", buf)
	}
	// CloseWrite must reach the wrapped connection rather than closing both
	// directions immediately.
	if cw, ok := res.c.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
}

// TestGatedListenerRejectsWithReset checks a failing gate resets the client
// connection, so the failure is visible immediately on Linux and OpenBSD where
// the kernel already completed the handshake.
func TestGatedListenerRejectsWithReset(t *testing.T) {
	ln, err := ListenGated("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatalf("ListenGated: %v", err)
	}
	defer ln.Close()

	gateErr := errors.New("target unreachable")
	gated := make(chan error, 1)
	go func() {
		c, err := ln.Accept(func() (net.Conn, error) { return nil, gateErr })
		if c != nil {
			_ = c.Close()
		}
		gated <- err
	}()

	client, err := net.DialTimeout("tcp4", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	select {
	case err := <-gated:
		if !errors.Is(err, gateErr) {
			t.Fatalf("accept error = %v, want the gate's", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gated accept did not return")
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, rerr := client.Read(buf); rerr == nil {
		t.Fatal("the rejected connection must not stay open")
	}
}
