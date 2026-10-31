package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileChannel writes one JSON object per line to a local file.
type FileChannel struct {
	name string
	path string
	mu   sync.Mutex
}

// NewFileChannel opens (or creates) path and returns a channel that appends.
func NewFileChannel(name, path string) (*FileChannel, error) {
	if path == "" {
		return nil, fmt.Errorf("file channel: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("file channel: mkdir: %w", err)
	}
	return &FileChannel{name: name, path: path}, nil
}

// Name returns the configured channel name.
func (c *FileChannel) Name() string { return c.name }

// Deliver appends a to the file as one JSON line.
func (c *FileChannel) Deliver(ctx context.Context, a Alert) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("file channel: encode: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("file channel: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("file channel: write: %w", err)
	}
	return f.Sync()
}