//go:build windows

package main

// Windows notifications, chosen at runtime:
//
//   - Windows 10 / Server 2016 and later: a WinRT toast through PowerShell
//     (the former and only path). If that PowerShell call fails, the
//     balloon below is used instead.
//   - Windows 7 / 8.1 / Server 2008 R2 / 2012 / 2012 R2: WinRT toasts are
//     not reachable there (the script needs PowerShell 5 `[Type]::new()` and
//     Windows 10's toast activation model), so the tray shows a classic
//     balloon on its own notification-area icon: Shell_NotifyIconW(NIM_MODIFY,
//     NIF_INFO). Windows 8 / 8.1 render that balloon as a toast themselves.
//
// The balloon targets the icon created by github.com/getlantern/systray: its
// hidden window (class "SystrayClass", owned by THIS process — other programs
// may use the same library and class) and icon ID 100 (systray_windows.go
// initInstance). NIM_MODIFY with only NIF_INFO leaves the icon and tooltip
// untouched.

import (
	"fmt"
	"log"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                 = windows.NewLazySystemDLL("user32.dll")
	shell32                = windows.NewLazySystemDLL("shell32.dll")
	procEnumWindows        = user32.NewProc("EnumWindows")
	procGetClassNameW      = user32.NewProc("GetClassNameW")
	procGetWindowThreadPID = user32.NewProc("GetWindowThreadProcessId")
	procShellNotifyIconW   = shell32.NewProc("Shell_NotifyIconW")
)

const (
	systrayClassName = "SystrayClass"
	systrayIconID    = 100

	nimModify   = 0x00000001
	nifInfo     = 0x00000010
	niifInfo    = 0x00000001
	niifNoSound = 0x00000010
)

// notifyIconDataW is NOTIFYICONDATAW (Vista+ layout, valid on Windows 7+).
type notifyIconDataW struct {
	CbSize            uint32
	HWnd              windows.Handle
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	HIcon             windows.Handle
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
	GUIDItem          windows.GUID
	HBalloonIcon      windows.Handle
}

// windowsMajorVersion: the real version (RtlGetVersion ignores the
// compatibility manifest lies of GetVersionEx).
func windowsMajorVersion() uint32 {
	return windows.RtlGetVersion().MajorVersion
}

func showWindowsNotification(title, message string) {
	if windowsMajorVersion() >= 10 {
		if err := showWinRTToast(title, message); err == nil {
			return
		}
	}
	if err := showBalloon(title, message); err != nil {
		log.Printf("notification failed: %v", err)
	}
}

func showWinRTToast(title, message string) error {
	script := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
$template = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>%s</text>
      <text>%s</text>
    </binding>
  </visual>
</toast>
"@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Obliance Agent").Show($toast)
`, escapeXML(title), escapeXML(message))
	return hiddenCmd("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Run()
}

// EnumWindows callback: created ONCE (syscall.NewCallback slots are limited
// and never freed); its per-call state lives in enumState under enumMu.
var (
	enumMu    sync.Mutex
	enumState struct {
		pid   uint32
		found windows.Handle
	}
	enumCallback = syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var wpid uint32
		procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&wpid)))
		if wpid != enumState.pid {
			return 1
		}
		var buf [64]uint16
		n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n > 0 && windows.UTF16ToString(buf[:n]) == systrayClassName {
			enumState.found = windows.Handle(hwnd)
			return 0 // stop
		}
		return 1
	})
)

// findSystrayWindow returns this process's systray window (0 if not found).
func findSystrayWindow() windows.Handle {
	enumMu.Lock()
	defer enumMu.Unlock()
	enumState.pid = uint32(windows.GetCurrentProcessId())
	enumState.found = 0
	procEnumWindows.Call(enumCallback, 0)
	return enumState.found
}

// copyUTF16 copies s into dst, truncated, NUL-terminated.
func copyUTF16(dst []uint16, s string) {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func showBalloon(title, message string) error {
	hwnd := findSystrayWindow()
	if hwnd == 0 {
		return fmt.Errorf("tray window not found")
	}
	nid := notifyIconDataW{
		HWnd:              hwnd,
		UID:               systrayIconID,
		UFlags:            nifInfo,
		UTimeoutOrVersion: 10000, // ms (ignored since Vista: system setting)
		DwInfoFlags:       niifInfo,
	}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	copyUTF16(nid.SzInfoTitle[:], title)
	copyUTF16(nid.SzInfo[:], message)
	r, _, err := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
	if r == 0 {
		return fmt.Errorf("Shell_NotifyIconW: %v", err)
	}
	return nil
}
