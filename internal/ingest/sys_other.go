//go:build !unix

package ingest

import "os"

// inodeOf is unavailable on this platform. Rotation is then detected only by
// truncation; see docs/limitations.md.
func inodeOf(fi os.FileInfo) uint64 { return 0 }
