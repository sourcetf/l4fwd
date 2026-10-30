//go:build !windows

// Command l4fwd-embed is a placeholder so "go build ./..." works on Linux and
// OpenBSD; embedding a Win32 manifest only makes sense on Windows.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "l4fwd-embed: 只有 Windows 构建需要嵌入清单与版本资源")
	os.Exit(2)
}
