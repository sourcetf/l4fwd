//go:build !windows

// Package platform holds the operating system helpers the CLI and dashboard
// need: elevation checks, opening a browser, a single instance lock and the
// firewall integration (Windows only).
package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

// ErrUnsupported is returned by helpers that only exist on Windows.
var ErrUnsupported = errors.New("this feature is only available on Windows")

// IsElevated reports whether the process can open raw sockets. Both Linux and
// OpenBSD need root for that (Linux can instead grant CAP_NET_RAW to the binary).
func IsElevated() bool { return os.Geteuid() == 0 }

// PrivilegeHint names the privilege raw forwarding needs on this system.
func PrivilegeHint() string {
	switch runtime.GOOS {
	case "linux":
		return "root 或 CAP_NET_RAW（sudo setcap cap_net_raw+ep ./l4fwd 也可以）"
	default:
		return "root"
	}
}

// Elevate is not available off Windows: there is no UAC equivalent that can be
// triggered without a terminal. The restart path falls back to re-exec.
func Elevate([]string) error { return ErrUnsupported }

// SingleInstance guards against two copies fighting over the same ports.
type SingleInstance struct{ f *os.File }

// Acquire takes an exclusive flock on a file in the temp directory; it returns
// nil when another instance holds it.
func Acquire(name string) (*SingleInstance, error) {
	path := filepath.Join(os.TempDir(), name+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, nil
		}
		return nil, err
	}
	return &SingleInstance{f: f}, nil
}

// Release drops the lock.
func (s *SingleInstance) Release() {
	if s == nil || s.f == nil {
		return
	}
	_ = syscall.Flock(int(s.f.Fd()), syscall.LOCK_UN)
	_ = s.f.Close()
	s.f = nil
}

// FirewallSupported reports whether automatic inbound firewall rules exist.
// Linux distributions and OpenBSD each have their own packet filter with its own
// configuration model, so the tool does not touch them; the dashboard hides the
// button and the README lists the manual commands.
func FirewallSupported() bool { return false }

// FirewallRule describes an inbound allow rule (Windows shape).
type FirewallRule struct {
	Name    string
	Port    int
	Proto   string
	Profile string
}

// AddFirewallRule explains the manual step instead of changing the host's
// packet filter.
func AddFirewallRule(r FirewallRule) error {
	return fmt.Errorf("自动放行仅支持 Windows；%s 请手动放行 %d/%s%s", runtime.GOOS, r.Port, r.Proto, manualFirewallHint())
}

// DeleteFirewallRule is unsupported.
func DeleteFirewallRule(string) error { return ErrUnsupported }

// FirewallRuleExists always reports false off Windows.
func FirewallRuleExists(string) bool { return false }

// EnsureFirewallRule is unsupported.
func EnsureFirewallRule(FirewallRule) (bool, error) { return false, ErrUnsupported }

// FirewallStatus mirrors the Windows type; Supported is false here so the
// dashboard does not warn about something it cannot check.
type FirewallStatus struct {
	Checked   bool     `json:"checked"`
	Supported bool     `json:"supported"`
	Missing   []string `json:"missing,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// InspectFirewall reports that firewall inspection is not available.
func InspectFirewall([]string) FirewallStatus {
	return FirewallStatus{Checked: true, Supported: false}
}

// manualFirewallHint returns the platform specific command a user can run.
func manualFirewallHint() string {
	switch runtime.GOOS {
	case "linux":
		return "（例如：sudo ufw allow 8080/tcp，或 nft/iptables 对应规则）"
	case "openbsd":
		return "（在 /etc/pf.conf 里加 pass in proto tcp to port 8080，然后 pfctl -f /etc/pf.conf）"
	}
	return ""
}

// SystemRoot is meaningless off Windows.
func SystemRoot() string { return "" }

// OpenInBrowser launches the default handler for url.
func OpenInBrowser(url string) error {
	for _, name := range []string{"xdg-open", "sensible-browser", "firefox"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, url)
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			continue
		}
		return nil
	}
	return errors.New("找不到 xdg-open，无法自动打开浏览器（用 -no-browser 可跳过）")
}

// HideConsoleWindow does nothing outside Windows.
func HideConsoleWindow() {}
