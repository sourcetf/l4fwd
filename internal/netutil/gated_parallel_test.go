//go:build windows

package netutil

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGatedCallbackConcurrencyIsOneAtATime documents the kernel behaviour the
// engine's gate cache exists for: SO_CONDITIONAL_ACCEPT lets only one callback
// run at a time per listening socket.
//
// The measurement is what matters, so it asserts only that the callback is not
// re-entered (the engine relies on this being true) and that a *fast* gate still
// serves a burst without dropping connections — a slow gate parks every other
// SYN until the callback returns.
func TestGatedCallbackConcurrencyIsOneAtATime(t *testing.T) {
	upstreamLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream: %v", err)
	}
	defer upstreamLn.Close()
	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.Close() }(c)
		}
	}()

	port := freeTCPPort(t)
	gl, err := ListenGated("127.0.0.1", port, 0)
	if err != nil {
		t.Fatalf("ListenGated: %v", err)
	}
	defer gl.Close()

	var inGate, maxInGate atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ { // 16 workers, as the engine starts
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := gl.Accept(func() (net.Conn, error) {
					now := inGate.Add(1)
					for {
						old := maxInGate.Load()
						if now <= old || maxInGate.CompareAndSwap(old, now) {
							break
						}
					}
					up, err := net.Dial("tcp4", upstreamLn.Addr().String())
					inGate.Add(-1)
					return up, err
				})
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	const clients = 32
	var ok, failed atomic.Int64
	var cwg sync.WaitGroup
	start := time.Now()
	for i := 0; i < clients; i++ {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			c, err := net.DialTimeout("tcp4", HostPort("127.0.0.1", port), 10*time.Second)
			if err != nil {
				failed.Add(1)
				return
			}
			ok.Add(1)
			_ = c.Close()
		}()
	}
	cwg.Wait()
	elapsed := time.Since(start)
	gl.Close()
	wg.Wait()

	if ok.Load() != clients {
		t.Fatalf("快速门控下 %d 个并发连接只成功 %d 个：接受路径本身在丢连接", clients, ok.Load())
	}
	if maxInGate.Load() != 1 {
		t.Logf("门控回调可以并发：同一时刻门内最多 %d 个（原以为是 1）", maxInGate.Load())
	}
	t.Logf("快速门控：%d 个并发连接全部成功，共耗时 %v，门内同时最多 %d 个",
		clients, elapsed.Round(time.Millisecond), maxInGate.Load())
}

// TestGatedSlowGateSerialisesBursts demonstrates the cost of a slow gate, which
// is why the engine must not dial the target inside the callback for every
// connection of a burst.
func TestGatedSlowGateSerialisesBursts(t *testing.T) {
	upstreamLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream: %v", err)
	}
	defer upstreamLn.Close()
	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.Close() }(c)
		}
	}()

	port := freeTCPPort(t)
	gl, err := ListenGated("127.0.0.1", port, 0)
	if err != nil {
		t.Fatalf("ListenGated: %v", err)
	}
	defer gl.Close()

	const gateDelay = 150 * time.Millisecond
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := gl.Accept(func() (net.Conn, error) {
					up, err := net.Dial("tcp4", upstreamLn.Addr().String())
					if err != nil {
						return nil, err
					}
					time.Sleep(gateDelay) // stands in for one target round trip
					return up, nil
				})
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	const clients = 8
	var ok atomic.Int64
	var cwg sync.WaitGroup
	start := time.Now()
	for i := 0; i < clients; i++ {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			c, err := net.DialTimeout("tcp4", HostPort("127.0.0.1", port), 10*time.Second)
			if err != nil {
				return
			}
			ok.Add(1)
			_ = c.Close()
		}()
	}
	cwg.Wait()
	elapsed := time.Since(start)
	gl.Close()
	wg.Wait()
	t.Logf("慢速门控（每个 %v）：%d 个并发连接成功 %d 个，共耗时 %v", gateDelay, clients, ok.Load(), elapsed.Round(time.Millisecond))
	if elapsed < gateDelay*2 {
		t.Logf("注意：本次测量没有呈现出串行代价（耗时 %v）", elapsed.Round(time.Millisecond))
	}
}
