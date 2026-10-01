//go:build windows

package netutil

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestConditionCallbackArityDeliversSlotKey pins the invariant the gate callback
// depends on: dwCallbackData arrives as the value passed to WSAAccept only when
// the callback's declared parameter list matches the kernel's calling
// convention.
//
// WSAAccept invokes the condition function with four register arguments and four
// stack arguments on x64 (lpCallerId, lpCallerData, lpSQOS, lpGQOS, lpCalleeId,
// lpCalleeData, g, dwCallbackData). The runtime builds the Go frame from the
// declared signature, so declaring one parameter too many makes dwCallbackData
// read past the frame and arrive as garbage. With the gate keyed by that value,
// the symptom is that *every* connection is refused, which is easy to misread as
// "the target is down".
func TestConditionCallbackArityDeliversSlotKey(t *testing.T) {
	const want = 0xdeadbeef
	cases := []struct {
		name    string
		makeCB  func(func(uintptr) uintptr) uintptr
		wantKey bool
	}{
		{"八参数（WSAAccept 约定）", cbArity8, true},
		{"九参数（多一个）", cbArity9, false},
	}
	for _, tc := range cases {
		port := freeTCPPort(t)
		gl, err := ListenGated("127.0.0.1", port, 0)
		if err != nil {
			t.Fatalf("ListenGated: %v", err)
		}
		got := make(chan uintptr, 1)
		cb := tc.makeCB(func(data uintptr) uintptr {
			select {
			case got <- data:
			default:
			}
			return cfReject
		})
		go func() {
			c, err := net.DialTimeout("tcp4", HostPort("127.0.0.1", port), 5*time.Second)
			if err == nil {
				time.Sleep(150 * time.Millisecond)
				_ = c.Close()
			}
		}()
		go func() { _, _ = rawWSAAccept(gl.fd, cb, want) }()

		select {
		case data := <-got:
			t.Logf("%s：dwCallbackData=0x%x", tc.name, data)
			if tc.wantKey && data != want {
				t.Errorf("%s：dwCallbackData=0x%x，期望 0x%x —— 门控会把每个连接都拒绝掉", tc.name, data, want)
			}
			if !tc.wantKey && data == want {
				t.Logf("%s：本次仍拿到了正确值（属实现细节，不可依赖）", tc.name)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s：回调没有被调用", tc.name)
		}
		gl.Close()
	}
}

// cbArity8 registers a condition function with WSAAccept's documented parameters.
func cbArity8(fn func(data uintptr) uintptr) uintptr {
	return syscall.NewCallback(func(_, _, _, _, _, _ uintptr, _ *uintptr, data uintptr) uintptr {
		return fn(data)
	})
}

// cbArity9 registers one with an extra parameter.
func cbArity9(fn func(data uintptr) uintptr) uintptr {
	return syscall.NewCallback(func(_, _, _, _, _, _, _ uintptr, _ *uintptr, data uintptr) uintptr {
		return fn(data)
	})
}

// rawWSAAccept performs one WSAAccept with the given callback and data.
func rawWSAAccept(fd windows.Handle, cb, data uintptr) (windows.Handle, error) {
	var addr windows.RawSockaddrAny
	addrLen := int32(unsafe.Sizeof(addr))
	r1, _, callErr := procWSAAccept.Call(uintptr(fd),
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&addrLen)), cb, data)
	if int32(r1) == -1 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, errors.New("WSAAccept failed")
	}
	return windows.Handle(r1), nil
}
