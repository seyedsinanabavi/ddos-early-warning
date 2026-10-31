package ingest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTailer_ReadsAndRecoversFromRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got []string
	tl := NewTailer(path)
	tl.PollEvery = 20 * time.Millisecond
	tl.OnLine = func(s string) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, s)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = tl.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout: got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Append one line.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("line3\n")
	_ = f.Close()

	deadline = time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout on append: got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Rotate: rename old, create new with different content.
	rotated := path + ".1"
	_ = os.Rename(path, rotated)
	if err := os.WriteFile(path, []byte("fresh1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		last := ""
		if len(got) > 0 {
			last = got[len(got)-1]
		}
		mu.Unlock()
		if last == "fresh1\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout on rotation: got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
