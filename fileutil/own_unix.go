//go:build unix

package fileutil

import (
	"os"
	"syscall"
)

// ownFile reports whether fi is user uid's file with none of the deny
// permission bits.
func ownFile(fi os.FileInfo, uid int, deny os.FileMode) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid && fi.Mode().Perm()&deny == 0
}
