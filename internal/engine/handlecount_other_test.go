//go:build !windows

package engine

import "fmt"

// osHandleCount is unavailable off Windows; return a sentinel so the caller can
// skip comparisons.
func osHandleCount() int { return -1 }

var _ = fmt.Sprint
