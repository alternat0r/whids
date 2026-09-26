//go:build windows
// +build windows

package agent

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// wnetGetConnection maps a drive letter to the UNC server share it is
// connected to (mpr.dll). It is used to resolve the agent's own executable
// to the same canonical UNC path that Sysmon reports, so the agent can
// recognize itself when launched from a mapped network drive.
var wnetGetConnection = syscall.NewLazyDLL("mpr.dll").NewProc("WNetGetConnectionW")

// mapDriveLetterToUNC returns the UNC form of path when path points to a
// file on a mapped network drive. For example, when Z: is mapped to
// \\vbox\test, "Z:\whids.exe" resolves to "\\vbox\test\whids.exe". For local
// (or non drive-letter) paths it returns the empty string, so the original
// path is used unchanged.
func mapDriveLetterToUNC(path string) string {
	// only handle absolute drive-letter paths, e.g. "Z:\foo\bar.exe"
	if len(path) < 3 || path[1] != ':' {
		return ""
	}
	root := path[:2] // "Z:"

	const maxPath = 260
	remote := make([]uint16, maxPath)
	ret, _, _ := wnetGetConnection.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(root))),
		uintptr(unsafe.Pointer(&remote[0])),
		uintptr(maxPath),
	)
	if ret != 0 {
		// not a mapped network drive (e.g. ERROR_INVALID_FUNCTION) or an error
		return ""
	}
	uncRoot := syscall.UTF16ToString(remote) // "\\vbox\test"
	if uncRoot == "" {
		return ""
	}
	rel := strings.TrimPrefix(path[len(root):], `\`) // "whids.exe" or "sub\whids.exe"
	return filepath.Join(uncRoot, rel)
}
