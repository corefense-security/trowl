//go:build !linux && !darwin

package status

import (
	"os"
	"strconv"
)

// termWidth is COLUMNS, else 80. These systems aren't asked for the terminal's size.
func termWidth() int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c
	}
	return 80
}
