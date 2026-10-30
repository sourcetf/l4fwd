// Package e2e drives the real l4fwd binary end to end: real TCP/UDP/raw traffic
// through the compiled binary, plus the dashboard API.
//
// The raw protocol tests need two addresses that play "client" and "target" on
// the same machine. Linux and OpenBSD treat 127.0.0.0/8 as local, so they use
// 127.0.0.2 and 127.0.0.3; Windows needs real aliases (scripts/e2e-aliases.ps1).
// Addresses are configurable through the L4FWD_E2E_* environment variables;
// tests skip themselves when the addresses are missing.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type rawPacket struct {
	src, dst net.IP
	proto    uint8
	sport    uint16
	dport    uint16
	body     []byte
	hasPorts bool
	id       uint16
	fragOff  uint16
	flags    uint8
	received time.Time
}

// recvOne waits for one packet matching the filter, or fails the test.
func (r *rawSock) recvOne(t *testing.T, timeout time.Duration, filter func(rawPacket) bool) rawPacket {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case p := <-r.packets:
			if filter(p) {
				return p
			}
		case <-deadline:
			t.Fatalf("no matching packet within %s", timeout)
			return rawPacket{}
		}
	}
}

// ---------- environment ----------

func envIP(name, fallback string) net.IP {
	v := os.Getenv(name)
	if v == "" {
		v = fallback
	}
	return net.ParseIP(v).To4()
}

// requireAliases skips the test when the helper addresses are not configured.
func requireAliases(t *testing.T) (client, listen, target net.IP) {
	t.Helper()
	defClient, defListen, defTarget := e2eDefaults()
	client = envIP("L4FWD_E2E_CLIENT", defClient)
	listen = envIP("L4FWD_E2E_LISTEN", defListen)
	target = envIP("L4FWD_E2E_TARGET", defTarget)
	if client == nil || listen == nil || target == nil {
		t.Skip("L4FWD_E2E_CLIENT/LISTEN/TARGET 未配置")
	}
	if !isLocalAddress(client) || !isLocalAddress(target) {
		t.Skipf("地址 %v/%v 不是本机地址；Windows 上先运行 scripts/e2e-aliases.ps1 -Add（需管理员）", client, target)
	}
	if !isElevated() {
		t.Skip("原始套接字测试需要 " + privilegeName())
	}
	return client, listen, target
}

func isLocalAddress(ip net.IP) bool {
	// Linux and OpenBSD own the whole 127.0.0.0/8 block; the interface list only
	// carries 127.0.0.1/8, so a loopback address never matches below.
	if runtime.GOOS != "windows" && ip.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var got net.IP
		switch v := a.(type) {
		case *net.IPNet:
			got = v.IP
		case *net.IPAddr:
			got = v.IP
		}
		if got != nil && got.To4() != nil && got.Equal(ip) {
			return true
		}
	}
	return false
}

// ---------- process control ----------

type agent struct {
	cmd    *exec.Cmd
	dir    string
	webURL string
	logs   *threadSafeBuffer
}

type threadSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func binaryPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("L4FWD_BIN"); p != "" {
		return p
	}
	exe, err := os.Executable()
	if err == nil {
		// The test binary lives in a temp dir; the agent is built next to it by
		// scripts/e2e.sh, so look there first.
		candidate := filepath.Join(filepath.Dir(exe), e2eBinName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	candidate := filepath.Join("..", "..", "bin", e2eBinName)
	if abs, err := filepath.Abs(candidate); err == nil {
		return abs
	}
	return candidate
}

// startAgent launches l4fwd with a temporary config and waits for the dashboard.
func startAgent(t *testing.T, rules []map[string]any, webAddr string) *agent {
	t.Helper()
	bin := binaryPath(t)
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("l4fwd 可执行文件不存在 (%s)，先执行 scripts/build.sh", bin)
	}
	dir := t.TempDir()
	cfg := map[string]any{
		"version": 1,
		"settings": map[string]any{
			"logLevel": "debug", "dialTimeoutSec": 5, "udpSessionTTLSec": 5,
			"bufferKB": 64, "samplerMs": 500,
		},
		"web":   map[string]any{"enabled": true, "listen": webAddr, "openBrowser": false, "username": "", "password": ""},
		"rules": rules,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	logs := &threadSafeBuffer{}
	cmd := exec.Command(bin, "-c", cfgPath, "-no-browser", "-web", webAddr, "-log-level", "debug")
	cmd.Dir = dir
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.Env = append(os.Environ(), "L4FWD_E2E=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	a := &agent{cmd: cmd, dir: dir, webURL: "http://" + webAddr, logs: logs}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("---- agent log ----\n%s", logs.String())
		}
	})

	// Wait for the dashboard to answer.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(a.webURL + "/api/overview")
		if err == nil {
			_ = resp.Body.Close()
			return a
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("agent did not start listening on %s\n%s", webAddr, logs.String())
	return nil
}

// freePort returns a localhost port a TCP listener can bind.
//
// The number is asked for over UDP and then verified on TCP, because on Windows
// the system reserves ranges of the port space for itself (Hyper-V / winnat
// "excluded port ranges"): a bind into one of those fails with WSAEACCES —
// "An attempt was made to access a socket in a way forbidden by its access
// permissions" — even right after another socket released the same number.
func freePort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("free port: %v", err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		_ = pc.Close()

		ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port
	}
	t.Fatal("找不到一个可用的本地端口")
	return 0
}

// ---------- tests ----------

// TestAgentDashboardAndRuleAPI is a black box check of the management surface.
func TestAgentDashboardAndRuleAPI(t *testing.T) {
	webPort := freePort(t)
	webAddr := fmt.Sprintf("127.0.0.1:%d", webPort)
	a := startAgent(t, nil, webAddr)

	// The dashboard page must load.
	resp, err := http.Get(a.webURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("l4fwd")) {
		t.Fatalf("dashboard page looks wrong: status=%d len=%d", resp.StatusCode, len(body))
	}

	// Create a rule through the API.
	payload := `{"kind":"tcp","listenHost":"127.0.0.1","listenPort":18080,"targetHost":"127.0.0.1","targetPort":18081,"enabled":false,"name":"api-test"}`
	r, err := http.Post(a.webURL+"/api/rules", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /api/rules: %v", err)
	}
	var created struct {
		Rule struct {
			ID string `json:"id"`
		} `json:"rule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	_ = r.Body.Close()
	if created.Rule.ID == "" {
		t.Fatalf("rule ID missing in response")
	}

	// The overview must now contain the rule and it must not be running.
	resp, err = http.Get(a.webURL + "/api/overview")
	if err != nil {
		t.Fatalf("GET /api/overview: %v", err)
	}
	var overview struct {
		Rules []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
			Runtime struct {
				Running bool   `json:"running"`
				Error   string `json:"error"`
			} `json:"runtime"`
		} `json:"rules"`
		Totals map[string]any `json:"totals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	_ = resp.Body.Close()
	if len(overview.Rules) != 1 || overview.Rules[0].ID != created.Rule.ID {
		t.Fatalf("overview rules = %+v", overview.Rules)
	}
	if overview.Rules[0].Name != "api-test" {
		t.Fatalf("rule name = %q", overview.Rules[0].Name)
	}
	if overview.Rules[0].Runtime.Running {
		t.Fatal("a disabled rule must not be running")
	}

	// Enable it and make sure it actually binds the port.
	enable := `{"kind":"tcp","listenHost":"127.0.0.1","listenPort":18080,"targetHost":"127.0.0.1","targetPort":18081,"enabled":true,"name":"api-test"}`
	req, _ := http.NewRequest(http.MethodPut, a.webURL+"/api/rules/"+created.Rule.ID, strings.NewReader(enable))
	req.Header.Set("Content-Type", "application/json")
	pr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT rule: %v", err)
	}
	_ = pr.Body.Close()
	if pr.StatusCode != 200 {
		t.Fatalf("PUT rule status = %d", pr.StatusCode)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp4", "127.0.0.1:18080", 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := net.DialTimeout("tcp4", "127.0.0.1:18080", time.Second); err != nil {
		t.Fatalf("enabled rule did not bind its port: %v\n%s", err, a.logs.String())
	}

	// Delete it again.
	dreq, _ := http.NewRequest(http.MethodDelete, a.webURL+"/api/rules/"+created.Rule.ID, nil)
	dr, err := http.DefaultClient.Do(dreq)
	if err != nil {
		t.Fatalf("DELETE rule: %v", err)
	}
	_ = dr.Body.Close()
	if dr.StatusCode != 200 {
		t.Fatalf("DELETE status = %d", dr.StatusCode)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := net.DialTimeout("tcp4", "127.0.0.1:18080", 300*time.Millisecond); err == nil {
		t.Fatal("deleted rule still listening")
	}
}

// TestRawRelayCustomProtocolOverLoopback drives a made up IP protocol through
// the real binary using two alias addresses as client and target.
func TestRawRelayCustomProtocolOverLoopback(t *testing.T) {
	client, listen, target := requireAliases(t)
	const proto = 200

	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "raw200", "kind": "raw", "protocol": "200",
		"listenHost": listen.String(), "targetHost": target.String(),
		"enabled": true, "name": "e2e-raw-200", "udpSessionTTLSec": 5,
		// Bespoke protocols usually define a port header inside the payload;
		// this flag tells the relay to read and translate that pair.
		"payloadPorts": true,
	}
	_ = startAgent(t, []map[string]any{rule}, webAddr)

	cli := openRaw(t, proto, client)
	defer cli.Close()
	srv := openRaw(t, proto, target)
	defer srv.Close()

	const (
		clientPort = 31000
		serverPort = 41000
		body       = "custom-protocol-e2e"
	)

	// 1) client -> relay (addressed to the relay's own address)
	cli.send(t, client, listen, clientPort, serverPort, []byte(body), 101)

	// 2) the target must receive it from the relay's address, with a proxy
	//    source port and the destination port preserved.
	fwd := srv.recvOne(t, 5*time.Second, func(p rawPacket) bool {
		return p.proto == proto && p.dst.Equal(target) && bytes.Equal(p.body[4:], []byte(body))
	})
	if !fwd.src.Equal(listen) {
		t.Fatalf("forwarded source = %v, want the relay address %v", fwd.src, listen)
	}
	if fwd.dport != serverPort {
		t.Fatalf("forwarded destination port = %d, want %d", fwd.dport, serverPort)
	}
	if fwd.sport == clientPort {
		t.Fatalf("relay must translate the source port (got the client's %d)", fwd.sport)
	}

	// 3) the target answers: from target to the relay address on the port the
	//    relay used.
	reply := []byte("reply-e2e")
	srv.send(t, target, listen, serverPort, fwd.sport, reply, 102)

	// 4) the client must receive it appearing to come from the address it sent
	//    to, addressed back to the client's own port.
	back := cli.recvOne(t, 5*time.Second, func(p rawPacket) bool {
		return p.proto == proto && p.dst.Equal(client) && bytes.Equal(p.body[4:], reply)
	})
	if !back.src.Equal(listen) {
		t.Fatalf("reply source = %v, want %v", back.src, listen)
	}
	if back.sport != serverPort {
		t.Fatalf("reply source port = %d, want %d", back.sport, serverPort)
	}
	if back.dport != clientPort {
		t.Fatalf("reply destination port = %d, want the client's %d", back.dport, clientPort)
	}
}

// TestRawRelayBinaryPayloadPreserved makes sure a payload with NULs and high
// bytes survives the relay untouched.
func TestRawRelayBinaryPayloadPreserved(t *testing.T) {
	client, listen, target := requireAliases(t)
	const proto = 201

	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "raw201", "kind": "raw", "protocol": "201",
		"listenHost": listen.String(), "targetHost": target.String(),
		"enabled": true, "name": "e2e-raw-201", "udpSessionTTLSec": 5, "payloadPorts": true,
	}
	_ = startAgent(t, []map[string]any{rule}, webAddr)

	cli := openRaw(t, proto, client)
	defer cli.Close()
	srv := openRaw(t, proto, target)
	defer srv.Close()

	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	cli.send(t, client, listen, 32000, 42000, payload, 201)

	fwd := srv.recvOne(t, 5*time.Second, func(p rawPacket) bool {
		return p.proto == proto && p.dst.Equal(target) && len(p.body) >= 4+len(payload)
	})
	got := fwd.body[4:]
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d of %d bytes differ", diffCount(got, payload), len(payload))
	}
}

func diffCount(a, b []byte) int {
	n := 0
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			n++
		}
	}
	return n
}

// TestRawRelayLargeDatagramFragmenting verifies a datagram larger than the
// interface MTU still arrives intact at the target.
//
// Note on fragments: Windows reassembles inbound fragments before handing them
// to a raw socket (verified on this platform), so the relay forwards complete
// datagrams and never has to reassemble. Large packets are fragmented on the
// way out by the IP stack after the relay has rewritten them.
func TestRawRelayLargeDatagramFragmenting(t *testing.T) {
	client, listen, target := requireAliases(t)
	const proto = 202

	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "raw202", "kind": "raw", "protocol": "202",
		"listenHost": listen.String(), "targetHost": target.String(),
		"enabled": true, "name": "e2e-raw-202", "udpSessionTTLSec": 5, "payloadPorts": true,
	}
	_ = startAgent(t, []map[string]any{rule}, webAddr)

	cli := openRaw(t, proto, client)
	defer cli.Close()
	srv := openRaw(t, proto, target)
	defer srv.Close()

	// 3000 bytes of payload exceeds the 1500 byte MTU, so the stack must
	// fragment the forwarded datagram.
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i * 7 % 251)
	}
	cli.send(t, client, listen, 33000, 43000, payload, 777)

	got := srv.recvOne(t, 5*time.Second, func(p rawPacket) bool {
		return p.proto == proto && p.dst.Equal(target) && len(p.body) >= 4+len(payload)
	})
	if !bytes.Equal(got.body[4:4+len(payload)], payload) {
		t.Fatalf("large payload mismatch: %d of %d bytes differ",
			diffCount(got.body[4:], payload), len(payload))
	}
	if got.sport == 33000 {
		t.Fatalf("relay must translate the source port on large datagrams too")
	}
}

// TestTCPRelayThroughRealAgent drives a real TCP forward through the binary.
func TestTCPRelayThroughRealAgent(t *testing.T) {
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
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	listenPort := freePort(t)
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "tcp-e2e", "kind": "tcp",
		"listenHost": "127.0.0.1", "listenPort": listenPort,
		"targetHost": "127.0.0.1", "targetPort": backendPort,
		"enabled": true, "name": "e2e-tcp",
	}
	a := startAgent(t, []map[string]any{rule}, webAddr)

	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v\n%s", err, a.logs.String())
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("tcp-through-agent;"), 4000)
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload mismatch over %d bytes", len(msg))
	}

	// The dashboard must report the traffic.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(a.webURL + "/api/overview")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var ov struct {
			Totals struct {
				RxBytes int64 `json:"rxBytes"`
				TxBytes int64 `json:"txBytes"`
				Conns   int64 `json:"conns"`
			} `json:"totals"`
		}
		err = json.NewDecoder(resp.Body).Decode(&ov)
		_ = resp.Body.Close()
		if err == nil && ov.Totals.RxBytes >= int64(len(msg)) && ov.Totals.TxBytes >= int64(len(msg)) && ov.Totals.Conns >= 1 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("dashboard did not report the forwarded traffic\n%s", a.logs.String())
}

// TestUDTRelayThroughRealAgent drives a real UDP forward through the binary.
func TestUDTRelayThroughRealAgent(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteToUDP(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()

	listenPort := freePort(t)
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "udp-e2e", "kind": "udp",
		"listenHost": "127.0.0.1", "listenPort": listenPort,
		"targetHost": "127.0.0.1", "targetPort": backendPort,
		"enabled": true, "name": "e2e-udp", "udpSessionTTLSec": 5,
	}
	a := startAgent(t, []map[string]any{rule}, webAddr)

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("datagram-%d", i))
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		buf := make([]byte, 256)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v\n%s", i, err, a.logs.String())
		}
		if want := "echo:" + string(msg); string(buf[:n]) != want {
			t.Fatalf("datagram %d = %q, want %q", i, buf[:n], want)
		}
	}
}

// TestConfigHotReload verifies editing the config file on disk is picked up.
func TestConfigHotReload(t *testing.T) {
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	a := startAgent(t, nil, webAddr)

	cfgPath := filepath.Join(a.dir, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	port := freePort(t)
	cfg["rules"] = []map[string]any{{
		"id": "hot", "kind": "tcp", "listenHost": "127.0.0.1", "listenPort": port,
		"targetHost": "127.0.0.1", "targetPort": 1, "enabled": true, "name": "hot-reload",
	}}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, out, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("hot reload did not start the new rule\n%s", a.logs.String())
}

// TestTransparentTCPForwardingThroughAgent covers the TCP-shaped raw rule: a
// client that only opens a TCP connection must reach the real target port, and
// the connection must fail while the target is down.
func TestTransparentTCPForwardingThroughAgent(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
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
						_, _ = c.Write(append([]byte("tcp-target:"), buf[:n]...))
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	listenPort := freePort(t)
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "trans-e2e", "kind": "raw", "protocol": "tcp", "rawTransport": "transparent",
		"listenHost": "127.0.0.1", "listenPort": listenPort,
		"targetHost": "127.0.0.1", "targetPort": backendPort,
		"enabled": true, "name": "e2e-transparent-tcp",
	}
	a := startAgent(t, []map[string]any{rule}, webAddr)

	// Payload path.
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v\n%s", err, a.logs.String())
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("tcp-target:hello"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "tcp-target:hello" {
		t.Fatalf("payload = %q", got)
	}
	_ = c.Close()

	// Target down: the connection must stop working at once. On Windows the
	// handshake is refused (SO_CONDITIONAL_ACCEPT gates it); on Linux and OpenBSD
	// the kernel already completed the handshake, so the relay resets it and the
	// failure shows up on the first write or read.
	_ = backend.Close()
	time.Sleep(200 * time.Millisecond)
	rejected := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		probe, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
		if err != nil {
			rejected = true
			break
		}
		_ = probe.SetDeadline(time.Now().Add(2 * time.Second))
		_, werr := probe.Write([]byte("probe"))
		var rerr error
		if werr == nil {
			buf := make([]byte, 1)
			_, rerr = probe.Read(buf)
		}
		_ = probe.Close()
		if werr != nil || rerr != nil {
			rejected = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !rejected {
		t.Fatalf("connection kept working while the target was down\n%s", a.logs.String())
	}
}

// TestRulesBatchAPIToggles checks the dashboard's select-all controls, which
// talk to /api/rules/batch: several rules change in one request and the file on
// disk follows.
func TestRulesBatchAPIToggles(t *testing.T) {
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	a := startAgent(t, nil, webAddr)

	postJSON := func(path, body string) (int, string) {
		t.Helper()
		resp, err := http.Post(a.webURL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}

	// Create three rules and let each one bind: two TCP, one UDP.
	type created struct{ id string }
	var rules []created
	for i := 0; i < 3; i++ {
		payload := fmt.Sprintf(`{"kind":"tcp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":19000,"enabled":true,"name":"batch-%d"}`,
			19000+i, i)
		if i == 2 {
			payload = fmt.Sprintf(`{"kind":"udp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":19000,"enabled":true,"name":"batch-%d"}`,
				19002, i)
		}
		code, body := postJSON("/api/rules", payload)
		if code != 200 {
			t.Fatalf("create rule %d: HTTP %d %s", i, code, body)
		}
		var resp struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatalf("decode created rule: %v", err)
		}
		rules = append(rules, created{id: resp.Rule.ID})
	}

	ids := func() []string {
		out := make([]string, 0, len(rules))
		for _, r := range rules {
			out = append(out, r.id)
		}
		return out
	}
	idsJSON, _ := json.Marshal(ids())

	// Disable all three in one request.
	code, body := postJSON("/api/rules/batch",
		fmt.Sprintf(`{"action":"disable","ids":%s}`, idsJSON))
	if code != 200 {
		t.Fatalf("batch disable: HTTP %d %s", code, body)
	}
	var applied struct {
		Applied int      `json:"applied"`
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal([]byte(body), &applied); err != nil {
		t.Fatalf("decode batch response: %v", err)
	}
	if applied.Applied != 3 || len(applied.Missing) != 0 {
		t.Fatalf("batch disable reported applied=%d missing=%v", applied.Applied, applied.Missing)
	}

	// The listeners must be gone.
	ports := []int{19000, 19001, 19002}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		allClosed := true
		for _, p := range ports {
			c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", p), 200*time.Millisecond)
			if err == nil {
				_ = c.Close()
				allClosed = false
				break
			}
		}
		if allClosed {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, p := range ports {
		if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", p), 300*time.Millisecond); err == nil {
			_ = c.Close()
			t.Fatalf("port %d is still listening after batch disable\n%s", p, a.logs.String())
		}
	}

	// Enable one again.
	one := fmt.Sprintf(`{"action":"enable","ids":[%q]}`, rules[0].id)
	code, body = postJSON("/api/rules/batch", one)
	if code != 200 {
		t.Fatalf("batch enable: HTTP %d %s", code, body)
	}
	enableDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(enableDeadline) {
		if c, err := net.DialTimeout("tcp4", "127.0.0.1:19000", 300*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:19000", time.Second); err != nil {
		t.Fatalf("re-enabled rule is not listening: %v", err)
	} else {
		_ = c.Close()
	}

	// Delete the remaining two and verify they are gone from the file.
	delIDs, _ := json.Marshal([]string{rules[1].id, rules[2].id})
	code, body = postJSON("/api/rules/batch", fmt.Sprintf(`{"action":"delete","ids":%s}`, delIDs))
	if code != 200 {
		t.Fatalf("batch delete: HTTP %d %s", code, body)
	}
	cfgData, err := os.ReadFile(filepath.Join(a.dir, "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].ID != rules[0].id {
		t.Fatalf("config after batch delete has %d rules: %+v", len(cfg.Rules), cfg.Rules)
	}

	// Error paths.
	if code, _ := postJSON("/api/rules/batch", `{"action":"enable","ids":[]}`); code != http.StatusBadRequest {
		t.Fatalf("empty ids should be a 400, got %d", code)
	}
	if code, _ := postJSON("/api/rules/batch", `{"action":"explode","ids":["x"]}`); code != http.StatusBadRequest {
		t.Fatalf("unknown action should be a 400, got %d", code)
	}
	if code, _ := postJSON("/api/rules/batch", `{"action":"enable","ids":["nope"]}`); code != http.StatusNotFound {
		t.Fatalf("unknown ids should be a 404, got %d", code)
	}
}

// TestAllProtocolsRuleThroughAgent covers the "all" protocol rule: one rule
// carries TCP, UDP and a bespoke protocol number at the same local port.
func TestAllProtocolsRuleThroughAgent(t *testing.T) {
	client, listen, target := requireAliases(t)
	const customProto = 200

	// Target services: a TCP echo and a UDP echo on the same port, plus a raw
	// capture socket for the custom protocol.
	tcpLn, err := net.Listen("tcp4", fmt.Sprintf("%s:19400", target))
	if err != nil {
		t.Fatalf("tcp target: %v", err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: target, Port: 19400})
	if err != nil {
		t.Fatalf("udp target: %v", err)
	}
	defer udpLn.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpLn.WriteToUDP(append([]byte("udp:"), buf[:n]...), addr)
		}
	}()

	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "all-proto", "kind": "raw", "protocol": "all", "rawTransport": "transparent",
		"listenHost": listen.String(), "listenPort": 19401,
		"targetHost": target.String(), "targetPort": 19400,
		"enabled": true, "name": "e2e-all-protocols", "dialTimeoutSec": 3,
	}
	a := startAgent(t, []map[string]any{rule}, webAddr)

	// 1) TCP through the same local port.
	tcpConn, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:19401", listen), 3*time.Second)
	if err != nil {
		t.Fatalf("tcp dial: %v\n%s", err, a.logs.String())
	}
	if _, err := tcpConn.Write([]byte("via-tcp")); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	got := make([]byte, len("via-tcp"))
	_ = tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tcpConn, got); err != nil {
		t.Fatalf("tcp read: %v", err)
	}
	if string(got) != "via-tcp" {
		t.Fatalf("tcp echo = %q", got)
	}
	_ = tcpConn.Close()

	// 2) UDP on the same local port.
	udpConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: listen, Port: 19401})
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer udpConn.Close()
	if _, err := udpConn.Write([]byte("via-udp")); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	udpBuf := make([]byte, 512)
	_ = udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := udpConn.Read(udpBuf)
	if err != nil {
		t.Fatalf("udp read: %v\n%s", err, a.logs.String())
	}
	if string(udpBuf[:n]) != "udp:via-udp" {
		t.Fatalf("udp echo = %q", udpBuf[:n])
	}

	// 3) A bespoke protocol number on the same local port, observed at the target.
	srv := openRaw(t, customProto, target)
	defer srv.Close()
	cli := openRaw(t, customProto, client)
	defer cli.Close()
	cli.send(t, client, listen, 35000, 19401, []byte("via-raw"), 9101)
	fwd := srv.recvOne(t, 5*time.Second, func(p rawPacket) bool {
		return p.proto == customProto && p.dst.Equal(target) && bytes.HasSuffix(p.body, []byte("via-raw"))
	})
	if fwd.dport != 19401 {
		t.Fatalf("custom protocol destination port = %d, want 19401", fwd.dport)
	}

	// The dashboard shows the whole rule as one row.
	resp, err := http.Get(a.webURL + "/api/overview")
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	defer resp.Body.Close()
	var ov struct {
		Rules []struct {
			ID      string `json:"id"`
			Kind    string `json:"kind"`
			Enabled bool   `json:"enabled"`
			Runtime struct {
				Running bool `json:"running"`
			} `json:"runtime"`
		} `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if len(ov.Rules) != 1 || ov.Rules[0].ID != "all-proto" || !ov.Rules[0].Runtime.Running {
		t.Fatalf("expected exactly one running rule, got %+v", ov.Rules)
	}
}

// TestSSHRuleServesIPv6Localhost is the regression test for the reported "ssh
// forwarding fails" case: Windows resolves localhost to ::1 first and the bundled
// OpenSSH client does not fall back to 127.0.0.1, so a rule with a wildcard listen
// address must serve both loopback families.
func TestSSHRuleServesIPv6Localhost(t *testing.T) {
	// A target that speaks first, the way an SSH server does.
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
				_, _ = c.Write([]byte("SSH-2.0-test-target\r\n"))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
			}(c)
		}
	}()

	port := freePort(t)
	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "ssh-dual", "kind": "tcp",
		"listenHost": "", "listenPort": port,
		"targetHost": "127.0.0.1", "targetPort": backendPort,
		"enabled": true, "name": "e2e-ssh-dual",
	}
	_ = startAgent(t, []map[string]any{rule}, webAddr)

	// Both loopback families must reach the target and get its banner. This is the
	// shape of an SSH handshake: the server greets first.
	for _, host := range []string{"127.0.0.1", "::1"} {
		addr := fmt.Sprintf("[%s]:%d", host, port)
		if host == "127.0.0.1" {
			addr = fmt.Sprintf("%s:%d", host, port)
		}
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Errorf("dial %s failed: %v", addr, err)
			continue
		}
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Errorf("%s: no banner: %v", addr, err)
		} else if !strings.HasPrefix(string(buf[:n]), "SSH-2.0-") {
			t.Errorf("%s: banner = %q", addr, buf[:n])
		} else {
			t.Logf("%s -> %q", addr, strings.TrimSpace(string(buf[:n])))
		}
		_ = c.Close()
	}
}

// TestListenPortConflictIsReportedInDashboard covers the other common "forwarding
// fails" cause: the port is already taken by another program. The rule must report
// the conflict instead of appearing to run.
func TestListenPortConflictIsReportedInDashboard(t *testing.T) {
	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	defer other.Close()
	port := other.Addr().(*net.TCPAddr).Port

	webAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	rule := map[string]any{
		"id": "conflict", "kind": "tcp",
		"listenHost": "127.0.0.1", "listenPort": port,
		"targetHost": "127.0.0.1", "targetPort": 9,
		"enabled": true, "name": "e2e-conflict",
	}
	a := startAgent(t, []map[string]any{rule}, webAddr)

	deadline := time.Now().Add(5 * time.Second)
	var lastErr string
	for time.Now().Before(deadline) {
		resp, err := http.Get(a.webURL + "/api/overview")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var ov struct {
			Rules []struct {
				Runtime struct {
					Running bool   `json:"running"`
					Error   string `json:"error"`
				} `json:"runtime"`
			} `json:"rules"`
		}
		err = json.NewDecoder(resp.Body).Decode(&ov)
		_ = resp.Body.Close()
		if err == nil && len(ov.Rules) == 1 && ov.Rules[0].Runtime.Error != "" {
			lastErr = ov.Rules[0].Runtime.Error
			if ov.Rules[0].Runtime.Running {
				t.Fatalf("rule claims to be running while the port is taken")
			}
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr == "" {
		t.Fatalf("the port conflict was never surfaced to the dashboard\n%s", a.logs.String())
	}
	if !strings.Contains(lastErr, "端口") && !strings.Contains(strings.ToLower(lastErr), "bind") {
		t.Fatalf("unhelpful conflict message: %q", lastErr)
	}
	t.Logf("dashboard reports: %s", lastErr)
}
