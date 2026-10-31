package audit

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileWriter opens (or creates) a JSONL audit file and returns a Logger that
// appends to it. The caller owns the returned closer.
func FileWriter(path string) (*Logger, func() error, error) {
	if path == "" {
		return nil, nil, fmt.Errorf("audit: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, nil, fmt.Errorf("audit: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return New(f), f.Close, nil
}

// MultiWriter returns a Logger that writes to all non-nil loggers. Useful for
// file + stdout.
func MultiWriter(loggers ...*Logger) *Logger {
	var ws []*Logger
	for _, l := range loggers {
		if l != nil {
			ws = append(ws, l)
		}
	}
	if len(ws) == 0 {
		return nil
	}
	return &Logger{fanout: ws}
}