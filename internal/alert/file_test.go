package alert

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileChannel_AppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "alerts.log")
	ch, err := NewFileChannel("local", path)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Name() != "local" {
		t.Fatalf("name: %q", ch.Name())
	}
	for _, id := range []string{"a1", "a2"} {
		if err := ch.Deliver(context.Background(), Alert{ID: id, Service: "svc"}); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var a Alert
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatalf("bad line: %v", err)
		}
		ids = append(ids, a.ID)
	}
	if len(ids) != 2 || ids[0] != "a1" || ids[1] != "a2" {
		t.Fatalf("ids: %v", ids)
	}
}

func TestFileChannel_EmptyPath(t *testing.T) {
	if _, err := NewFileChannel("x", ""); err == nil {
		t.Fatal("empty path must fail")
	}
}

func TestFileChannel_CancelledContext(t *testing.T) {
	ch, _ := NewFileChannel("x", filepath.Join(t.TempDir(), "a.log"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ch.Deliver(ctx, Alert{ID: "a"}); err == nil {
		t.Fatal("cancelled context must return an error")
	}
}