//go:build !darwin || !cgo

package platform

import (
	"fmt"
)

// BlessPrivilegedHelper stub for non-Darwin platforms.
func BlessPrivilegedHelper(helperID string) error {
	return fmt.Errorf("SMJobBless is only supported on macOS Darwin")
}
