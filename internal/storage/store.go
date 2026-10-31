// Package storage persists per-service baselines so they survive restarts.
// The file-based implementation is the MVP; the interface allows a later
// replacement without touching the engine.
package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/baseline"
)

// BaselineStore persists the baseline of each service.
type BaselineStore interface {
	// Load returns the saved state. ok is false when nothing was saved yet.
	Load(service string) (st baseline.ProfileState, ok bool, err error)
	// Save replaces the saved state for service.
	Save(service string, st baseline.ProfileState) error
}

// serviceNameRe limits names to a safe file-name subset. This prevents path
// traversal through the service name.
var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// FileBaselineStore keeps one JSON file per service in Dir.
type FileBaselineStore struct {
	dir string
}

// NewFileBaselineStore creates dir if needed and returns a store that uses it.
func NewFileBaselineStore(dir string) (*FileBaselineStore, error) {
	if dir == "" {
		return nil, errors.New("storage: dir is empty")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("storage: create dir: %w", err)
	}
	return &FileBaselineStore{dir: dir}, nil
}

func (s *FileBaselineStore) path(service string) (string, error) {
	if !serviceNameRe.MatchString(service) {
		return "", fmt.Errorf("storage: invalid service name %q", service)
	}
	return filepath.Join(s.dir, "baseline-"+service+".json"), nil
}

// Load implements BaselineStore.
func (s *FileBaselineStore) Load(service string) (baseline.ProfileState, bool, error) {
	p, err := s.path(service)
	if err != nil {
		return baseline.ProfileState{}, false, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return baseline.ProfileState{}, false, nil
	}
	if err != nil {
		return baseline.ProfileState{}, false, fmt.Errorf("storage: read: %w", err)
	}
	st, err := baseline.UnmarshalState(b)
	if err != nil {
		return baseline.ProfileState{}, false, fmt.Errorf("storage: %s is corrupt: %w", filepath.Base(p), err)
	}
	return st, true, nil
}

// Save implements BaselineStore. It writes to a temporary file in the same
// directory, syncs it, and renames it over the target. A crash therefore
// leaves either the old or the new file, never a partial one.
func (s *FileBaselineStore) Save(service string, st baseline.ProfileState) error {
	p, err := s.path(service)
	if err != nil {
		return err
	}
	b, err := baseline.MarshalState(st)
	if err != nil {
		return fmt.Errorf("storage: encode: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("storage: create temp: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(stage string, err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("storage: %s: %w", stage, err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fail("write", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("storage: close: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("storage: rename: %w", err)
	}
	return nil
}
