package alert

import (
	"testing"
	"time"
)

func TestDedup_DisabledWhenCooldownZero(t *testing.T) {
	d := NewDedup(0)
	d.Mark("a", now)
	if seen, _ := d.Seen("a", now); seen {
		t.Fatal("zero cooldown must never suppress")
	}
}

func TestDedup_SeenWithinCooldownOnly(t *testing.T) {
	d := NewDedup(5 * time.Minute)
	if seen, _ := d.Seen("a", now); seen {
		t.Fatal("unknown id must not be seen")
	}
	d.Mark("a", now)
	if seen, prev := d.Seen("a", now.Add(4*time.Minute)); !seen || !prev.Equal(now) {
		t.Fatalf("within cooldown: seen=%v prev=%v", seen, prev)
	}
	if seen, _ := d.Seen("a", now.Add(5*time.Minute)); seen {
		t.Fatal("at exactly the cooldown the alert must be allowed again")
	}
}

func TestDedup_SeenDoesNotChangeState(t *testing.T) {
	d := NewDedup(time.Minute)
	for i := 0; i < 3; i++ {
		d.Seen("a", now)
	}
	if seen, _ := d.Seen("a", now); seen {
		t.Fatal("Seen must not record a delivery")
	}
}

func TestDedup_MarkOnZeroValueDoesNotPanic(t *testing.T) {
	d := &Dedup{Cooldown: time.Minute}
	d.Mark("a", now)
	if seen, _ := d.Seen("a", now); !seen {
		t.Fatal("mark on zero-value dedup must work")
	}
}

func TestDedup_AllowKeepsOldBehaviour(t *testing.T) {
	d := NewDedup(time.Minute)
	if ok, _ := d.Allow("a", now); !ok {
		t.Fatal("first allow must pass")
	}
	if ok, _ := d.Allow("a", now.Add(time.Second)); ok {
		t.Fatal("second allow within cooldown must be blocked")
	}
}

func TestDedup_Purge(t *testing.T) {
	d := NewDedup(time.Minute)
	d.Mark("old", now)
	d.Mark("new", now.Add(90*time.Second))
	d.Purge(now.Add(2 * time.Minute))
	if seen, _ := d.Seen("old", now.Add(2*time.Minute)); seen {
		t.Fatal("expired entry must be purged")
	}
	if seen, _ := d.Seen("new", now.Add(2*time.Minute)); !seen {
		t.Fatal("fresh entry must be kept")
	}
}