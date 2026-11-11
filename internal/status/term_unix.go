//go:build linux || darwin

package status

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// termWidth is the width of the terminal stderr is on. It is asked each time so a resize is
// followed. When it can't be asked, termWidth falls back to COLUMNS, then 80.
func termWidth() int {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stderr.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno == 0 && ws.Col > 0 {
		return int(ws.Col)
	}
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c
	}
	return 80
}
