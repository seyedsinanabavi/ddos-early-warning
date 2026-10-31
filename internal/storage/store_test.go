package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/baseline"
)

func TestFileStore_LoadMissing(t *testing.T) {
	s, err := NewFileBaselineStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := s.Load("svc")
	if err != nil || ok {
		t.Fatalf("missing: ok=%v err=%v", ok, err)
	}
}

func TestFileStore_RoundTripAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileBaselineStore(dir)

	p, _ := baseline.NewProfile(0.3, 1)
	at := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	p.Update(at, 42, 0.5, 0.01)
	if err := s.Save("public-web", p.State()); err != nil {
		t.Fatal(err)
	}

	// Simulate a restart: new store, new profile from disk.
	s2, _ := NewFileBaselineStore(dir)
	st, ok, err := s2.Load("public-web")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	restored, err := baseline.RestoreProfile(st)
	if err != nil {
		t.Fatal(err)
	}
	mean, _, ok := restored.RateStats(at)
	if !ok || mean != 42 {
		t.Fatalf("after restart: mean=%v ok=%v", mean, ok)
	}
}

func TestFileStore_CorruptFileIsError(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileBaselineStore(dir)
	if err := os.WriteFile(filepath.Join(dir, "baseline-svc.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load("svc"); err == nil {
		t.Fatal("corrupt file must be an error, not a silent cold start")
	}
}

func TestFileStore_RejectsUnsafeNames(t *testing.T) {
	s, _ := NewFileBaselineStore(t.TempDir())
	for _, name := range []string{"", "..", "../etc", "a/b", "a b", ".hidden", "x\x00y"} {
		if err := s.Save(name, baseline.ProfileState{}); err == nil {
			t.Fatalf("Save(%q) must fail", name)
		}
		if _, _, err := s.Load(name); err == nil {
			t.Fatalf("Load(%q) must fail", name)
		}
	}
}

func TestFileStore_SaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileBaselineStore(dir)
	p, _ := baseline.NewProfile(0.2, 1)
	for i := 0; i < 3; i++ {
		if err := s.Save("svc", p.State()); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "baseline-svc.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected files: %v", names)
	}
}

func TestNewFileBaselineStore_EmptyDir(t *testing.T) {
	if _, err := NewFileBaselineStore(""); err == nil {
		t.Fatal("empty dir must fail")
	}
}
