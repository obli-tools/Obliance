//go:build windows

package main

import (
	"testing"
	"unsafe"
)

// NOTIFYICONDATAW (Vista+ layout) is 976 bytes on 64-bit, 956 on 32-bit;
// Shell_NotifyIconW rejects a wrong cbSize on Windows 7.
func TestNotifyIconDataSize(t *testing.T) {
	want := uintptr(976)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 956
	}
	if got := unsafe.Sizeof(notifyIconDataW{}); got != want {
		t.Fatalf("sizeof(notifyIconDataW) = %d, want %d", got, want)
	}
}

func TestCopyUTF16Truncates(t *testing.T) {
	var buf [4]uint16
	copyUTF16(buf[:], "abcdefgh")
	if buf[3] != 0 || buf[0] != 'a' || buf[2] != 'c' {
		t.Fatalf("buf = %v", buf)
	}
}

func TestFindSystrayWindowNoneInTest(t *testing.T) {
	if h := findSystrayWindow(); h != 0 {
		t.Fatalf("unexpected systray window %v in a test process", h)
	}
	if err := showBalloon("t", "m"); err == nil {
		t.Fatal("showBalloon without tray window should fail cleanly")
	}
}
