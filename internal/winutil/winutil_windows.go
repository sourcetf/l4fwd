//go:build windows

// Package winutil contains Windows specific helpers: elevation checks, single
// instance locking, firewall rules and service installation.
package winutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsElevated reports whether the current process has administrator rights.
func IsElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

// Elevate relaunches the current executable with a UAC prompt and returns
// immediately; the caller should exit afterwards.
func Elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb := "runas"
	argLine := quoteArgs(args)
	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	argPtr, _ := syscall.UTF16PtrFromString(argLine)
	cwdPtr, _ := syscall.UTF16PtrFromString(mustGetwd())
	ret, _, lastErr := shellExecute.Call(
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		1, // SW_SHOWNORMAL
	)
	if ret <= 32 {
		if lastErr != nil && lastErr != syscall.Errno(0) {
			return fmt.Errorf("ShellExecute failed: %w", lastErr)
		}
		return fmt.Errorf("ShellExecute returned %d", ret)
	}
	return nil
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func quoteArgs(args []string) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if a == "" {
			parts = append(parts, `""`)
			continue
		}
		if strings.ContainsAny(a, " \t\"") {
			parts = append(parts, `"`+strings.ReplaceAll(a, `"`, `\"`)+`"`)
			continue
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

var shellExecute = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW")

// SingleInstance guards against running two copies that would fight over the
// same listening ports.
type SingleInstance struct {
	handle windows.Handle
}

// Acquire creates a named mutex; it returns nil when another instance holds it.
func Acquire(name string) (*SingleInstance, error) {
	namePtr, err := syscall.UTF16PtrFromString(`Global\` + name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateMutex(nil, false, namePtr)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, nil
		}
		return nil, err
	}
	// CreateMutex signals ERROR_ALREADY_EXISTS through GetLastError.
	if errno, _ := err.(syscall.Errno); errno == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(h)
		return nil, nil
	}
	if errno := windows.GetLastError(); errno == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(h)
		return nil, nil
	}
	return &SingleInstance{handle: h}, nil
}

// Release drops the mutex.
func (s *SingleInstance) Release() {
	if s == nil || s.handle == 0 {
		return
	}
	windows.ReleaseMutex(s.handle)
	windows.CloseHandle(s.handle)
	s.handle = 0
}

// FirewallRule describes a Windows firewall allow rule.
type FirewallRule struct {
	Name    string
	Port    int
	Proto   string // TCP or UDP
	Profile string // any | domain | private | public
}

// AddFirewallRule creates an inbound allow rule using netsh.
func AddFirewallRule(r FirewallRule) error {
	if r.Proto == "" {
		r.Proto = "TCP"
	}
	if r.Profile == "" {
		r.Profile = "any"
	}
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + r.Name,
		"dir=in", "action=allow",
		"protocol=" + r.Proto,
		"localport=" + fmt.Sprint(r.Port),
	}
	if !strings.EqualFold(r.Profile, "any") {
		args = append(args, "profile="+r.Profile)
	}
	return runNetsh(args)
}

// DeleteFirewallRule removes every rule with the given name.
func DeleteFirewallRule(name string) error {
	return runNetsh([]string{"advfirewall", "firewall", "delete", "rule", "name=" + name})
}

// FirewallRuleExists reports whether an inbound allow rule with this name is
// already present. netsh exits with code 1 and prints 没有与指定标准相匹配的规则
// when nothing matches.
func FirewallRuleExists(name string) bool {
	err := runNetsh([]string{"advfirewall", "firewall", "show", "rule", "name=" + name})
	return err == nil
}

// EnsureFirewallRule creates the rule when it is missing and reports whether it
// had to act, so a caller can tell "already allowed" from "just changed".
func EnsureFirewallRule(r FirewallRule) (created bool, err error) {
	if FirewallRuleExists(r.Name) {
		return false, nil
	}
	if err := AddFirewallRule(r); err != nil {
		return false, err
	}
	return true, nil
}

func runNetsh(args []string) error {
	exe := filepathJoin(SystemRoot(), "System32", "netsh.exe")
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("netsh %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}

// SystemRoot returns %SystemRoot% (usually C:\Windows).
func SystemRoot() string {
	if v := os.Getenv("SystemRoot"); v != "" {
		return v
	}
	return `C:\Windows`
}

func filepathJoin(parts ...string) string {
	out := ""
	for i, p := range parts {
		if i == 0 {
			out = strings.TrimRight(p, `\/`)
			continue
		}
		out += `\` + strings.Trim(p, `\/`)
	}
	return out
}

// OpenInBrowser launches the default handler for url.
func OpenInBrowser(url string) error {
	exe := filepathJoin(SystemRoot(), "System32", "rundll32.exe")
	cmd := exec.Command(exe, "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd.Start()
}

// HideConsoleWindow is used when running detached from a console.
func HideConsoleWindow() {
	if console := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow"); console.Find() == nil {
		hwnd, _, _ := console.Call()
		if hwnd != 0 {
			user32 := windows.NewLazySystemDLL("user32.dll").NewProc("ShowWindow")
			_, _, _ = user32.Call(hwnd, 0) // SW_HIDE
		}
	}
}

// FirewallStatus summarises whether the inbound ports of a rule are open.
type FirewallStatus struct {
	// Checked is false when the process is not elevated, so nothing can be said.
	Checked bool     `json:"checked"`
	Missing []string `json:"missing,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// InspectFirewall reports which of the given rule names are missing. It needs
// administrator rights because netsh refuses to enumerate otherwise.
func InspectFirewall(names []string) FirewallStatus {
	if len(names) == 0 {
		return FirewallStatus{Checked: true}
	}
	if !IsElevated() {
		return FirewallStatus{Error: "需要管理员权限才能检查防火墙规则"}
	}
	st := FirewallStatus{Checked: true}
	for _, n := range names {
		if !FirewallRuleExists(n) {
			st.Missing = append(st.Missing, n)
		}
	}
	return st
}
