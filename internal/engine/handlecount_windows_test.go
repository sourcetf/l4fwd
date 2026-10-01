package engine

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32Test          = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHandles = kernel32Test.NewProc("GetProcessHandleCount")
)

// osHandleCount reports how many kernel handles this process owns. Callers use it
// to detect leaked sockets; -1 means the count is unavailable.
func osHandleCount() int {
	var n uint32
	ret, _, _ := procGetProcessHandles.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&n)),
	)
	if ret == 0 {
		return -1
	}
	return int(n)
}
