//go:build !windows

// Package winutil is a stub on non Windows platforms so the CLI still builds.
package winutil

import (
	"errors"
	"os"
)

// ErrUnsupported is returned by every Windows only helper.
var ErrUnsupported = errors.New("this feature is only available on Windows")

// IsElevated always reports false off Windows.
func IsElevated() bool { return false }

// Elevate is unsupported.
func Elevate([]string) error { return ErrUnsupported }

// SingleInstance is a no-op handle.
type SingleInstance struct{}

// Acquire always succeeds off Windows.
func Acquire(string) (*SingleInstance, error) { return &SingleInstance{}, nil }

// Release does nothing.
func (s *SingleInstance) Release() {}

// FirewallRule mirrors the Windows type.
type FirewallRule struct {
	Name    string
	Port    int
	Proto   string
	Profile string
}

// AddFirewallRule is unsupported.
func AddFirewallRule(FirewallRule) error { return ErrUnsupported }

// DeleteFirewallRule is unsupported.
func DeleteFirewallRule(string) error { return ErrUnsupported }

// SystemRoot returns a conventional path.
func SystemRoot() string { return os.Getenv("SystemRoot") }

// OpenInBrowser is unsupported.
func OpenInBrowser(string) error { return ErrUnsupported }

// HideConsoleWindow does nothing.
func HideConsoleWindow() {}

// FirewallRuleExists always reports false off Windows.
func FirewallRuleExists(string) bool { return false }

// EnsureFirewallRule is unsupported.
func EnsureFirewallRule(FirewallRule) (bool, error) { return false, ErrUnsupported }

// FirewallStatus mirrors the Windows type.
type FirewallStatus struct {
	Checked bool     `json:"checked"`
	Missing []string `json:"missing,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// InspectFirewall is unsupported.
func InspectFirewall([]string) FirewallStatus {
	return FirewallStatus{Error: ErrUnsupported.Error()}
}
