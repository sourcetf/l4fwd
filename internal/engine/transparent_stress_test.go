package engine

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/stats"
)

// TestTransparentStress repeats the forward many times to surface races in the
// gated accept path.
func TestTransparentStress(t *testing.T) {
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
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "stress", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	lg := logx.New(logx.Debug, 200)
	st := stats.NewRuleStats()
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 3}, st, lg)
	if err := tr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tr.Stop()

	for i := 0; i < 40; i++ {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
		if err != nil {
			t.Fatalf("iteration %d: dial: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("payload-%02d", i))
		if _, err := c.Write(msg); err != nil {
			_ = c.Close()
			t.Fatalf("iteration %d: write: %v", i, err)
		}
		got := make([]byte, len(msg))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil {
			_ = c.Close()
			t.Fatalf("iteration %d: read: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			_ = c.Close()
			t.Fatalf("iteration %d: echo %q != %q", i, got, msg)
		}
		_ = c.Close()
	}
}
