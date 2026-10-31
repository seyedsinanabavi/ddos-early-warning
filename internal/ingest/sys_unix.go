//go:build unix

package ingest

import (
	"os"
	"syscall"
)

// inodeOf returns the inode of fi, or 0 when it is unavailable. Used to detect
// log rotation: a different inode at the same path means the file was replaced.
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
