//go:build !windows

package xsyscall

import (
	"syscall"
	"testing"
)

// LoadInstance is for cross-compile.
func LoadInstance(t *testing.T, inst []byte) uintptr {
	return 0
}

// SyscallN is for cross-compile.
func SyscallN(trap uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return 0, 0, 0
}
