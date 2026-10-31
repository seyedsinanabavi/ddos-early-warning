package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Tailer follows one log file and calls OnLine for each complete new line.
//
// Rotation handling: after draining the current file, the Tailer checks whether
// the path now names a different inode (rename + create). If so it finishes the
// old file, then reopens the path from offset 0. In-place truncation is handled
// by resetting the offset when the file is smaller than what was consumed.
//
// It polls instead of using fsnotify to keep the dependency surface small.
type Tailer struct {
	Path      string
	PollEvery time.Duration
	// OnLine receives each line including its trailing newline. An error stops
	// the Tailer.
	OnLine func(line string) error
}

// NewTailer returns a Tailer with a 250ms poll interval.
func NewTailer(path string) *Tailer {
	return &Tailer{Path: path, PollEvery: 250 * time.Millisecond}
}

// Run blocks until ctx is cancelled or OnLine returns an error.
func (t *Tailer) Run(ctx context.Context) error {
	if t.OnLine == nil {
		return errors.New("ingest: Tailer.OnLine is nil")
	}
	if t.PollEvery <= 0 {
		t.PollEvery = 250 * time.Millisecond
	}

	var (
		f      *os.File
		inode  uint64
		offset int64
	)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if f == nil {
			nf, err := os.Open(t.Path)
			if err != nil {
				// Not there yet (or briefly absent during rotation): wait.
				if err := t.sleep(ctx); err != nil {
					return err
				}
				continue
			}
			fi, err := nf.Stat()
			if err != nil {
				_ = nf.Close()
				if err := t.sleep(ctx); err != nil {
					return err
				}
				continue
			}
			f, inode, offset = nf, inodeOf(fi), 0
		}

		// In-place truncation (copytruncate): restart from the beginning.
		if fi, err := f.Stat(); err == nil && fi.Size() < offset {
			offset = 0
		}

		if err := t.drain(f, &offset); err != nil {
			return err
		}

		// Rotation: if the path now points at another file, the old one has
		// been fully drained, so switch to the new one.
		if inode != 0 {
			if pfi, err := os.Stat(t.Path); err == nil && inodeOf(pfi) != inode {
				if err := t.drain(f, &offset); err != nil {
					return err
				}
				_ = f.Close()
				f = nil
				continue
			}
		}

		if err := t.sleep(ctx); err != nil {
			return err
		}
	}
}

// drain reads all complete lines from offset onward and advances offset past
// them. A trailing partial line is left unread so it is re-read in full on the
// next poll.
func (t *Tailer) drain(f *os.File, offset *int64) error {
	if _, err := f.Seek(*offset, io.SeekStart); err != nil {
		return fmt.Errorf("ingest: seek %s: %w", t.Path, err)
	}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if errors.Is(err, io.EOF) {
			return nil // partial line or nothing new
		}
		if err != nil {
			return fmt.Errorf("ingest: read %s: %w", t.Path, err)
		}
		*offset += int64(len(line))
		if e := t.OnLine(line); e != nil {
			return fmt.Errorf("ingest: OnLine: %w", e)
		}
	}
}

func (t *Tailer) sleep(ctx context.Context) error {
	timer := time.NewTimer(t.PollEvery)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
