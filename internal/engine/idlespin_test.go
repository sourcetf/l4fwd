//go:build windows

package engine

import (
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"l4fwd/internal/config"
	"l4fwd/internal/logx"
	"l4fwd/internal/stats"
)

// selfCPU returns the CPU seconds this process has burned.
func selfCPU(t *testing.T) float64 {
	t.Helper()
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatalf("GetCurrentProcess: %v", err)
	}
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		t.Fatalf("GetProcessTimes: %v", err)
	}
	return float64(kernel.Nanoseconds()+user.Nanoseconds()) / 1e9
}

// TestTransparentIdleConnectionDoesNotSpin is the regression guard for the relay
// burning a whole core on an idle connection.
//
// The accepted client socket of a gated listener is driven by WinConn, which is
// non-blocking. A read that finds no data must park in WSAPoll; retrying the
// non-blocking receive in a loop instead spins at 100% CPU for as long as the
// connection sits idle — which, for a forwarded SSH prompt, is most of the time.
// The measurement is the process's own CPU time, so a spin is unmissable: one
// saturated core is roughly one CPU second per second of wall clock.
func TestTransparentIdleConnectionDoesNotSpin(t *testing.T) {
	// A backend that accepts and then says nothing at all.
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.Addr().(*net.TCPAddr).Port
	var release sync.Once
	held := make(chan struct{})
	releaseHold := func() { release.Do(func() {}); close(held) }
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		<-held
		_ = c.Close()
	}()

	listenPort := freePort(t)
	rule := &config.Rule{
		ID: "idle-spin", Kind: config.KindRaw, Protocol: "tcp", RawTransport: config.RawTransparent,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort, Enabled: true,
	}
	if err := rule.Validate(); err != nil {
		releaseHold()
		t.Fatalf("validate: %v", err)
	}
	lg := logx.New(logx.Error, 50)
	tr := NewTransparentTCPListener(rule, config.Settings{DialTimeoutSec: 3}, stats.NewRuleStats(), lg)
	if err := tr.Start(); err != nil {
		releaseHold()
		t.Fatalf("start: %v", err)
	}
	defer func() {
		releaseHold()
		tr.Stop()
	}()

	client, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", itoa(listenPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer client.Close()
	// One byte proves the relay is live; the connection then stays silent.
	if _, err := client.Write([]byte{'h'}); err != nil {
		t.Fatalf("write: %v", err)
	}

	const window = 1500 * time.Millisecond
	// Let the connection settle so connect/setup work is not counted.
	time.Sleep(150 * time.Millisecond)
	before := selfCPU(t)
	time.Sleep(window)
	burned := selfCPU(t) - before

	t.Logf("空闲 %v 内本进程 CPU 时间：%.3f 秒（自旋会接近 %.1f 秒）", window, burned, window.Seconds())
	if burned > 0.5 {
		t.Fatalf("空闲连接让进程烧掉 %.3f 秒 CPU（%v 窗口）：读路径在忙等而不是停在 WSAPoll", burned, window)
	}

	// The connection must still work after having been idle.
	if _, err := client.Write([]byte{'i'}); err != nil {
		t.Fatalf("write after idle: %v", err)
	}
}

// itoa avoids importing strconv in a file that mostly deals with sockets.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

var _ = io.EOF
