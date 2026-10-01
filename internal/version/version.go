// Package version holds build-time identity for the l4fwd binary.
package version

// These values are overridden at build time with -ldflags.
var (
	Version   = "1.0.0"
	Commit    = "dev"
	BuildTime = "unknown"
)

// String returns a human readable version string.
func String() string {
	return Version + " (" + Commit + ")"
}
