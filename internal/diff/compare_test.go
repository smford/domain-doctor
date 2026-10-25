package diff

import (
	"testing"
	"time"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestSnapshotDiffing(t *testing.T) {
	snap := &engine.ZoneSnapshot{
		Domain:    "example.com",
		Timestamp: time.Now(),
		Records: map[string][]string{
			"A":  {"192.0.2.1", "192.0.2.2"},
			"MX": {"10 mail.example.com"},
		},
	}

	// 1. Identical live report
	liveIdentical := &engine.DiagnosticReport{
		Domain: "example.com",
		Records: map[string][]string{
			"A":  {"192.0.2.2", "192.0.2.1"}, // Different order should be normalized
			"MX": {"10 mail.example.com"},
		},
	}

	diff1 := CompareSnapshotToLive(snap, liveIdentical)
	if diff1.HasDeltas {
		t.Fatalf("expected no deltas, got %v", diff1.Deltas)
	}

	// 2. Modified live report
	liveModified := &engine.DiagnosticReport{
		Domain: "example.com",
		Records: map[string][]string{
			"A":   {"192.0.2.1", "192.0.2.99"},
			"TXT": {"v=spf1 -all"},
		},
	}

	diff2 := CompareSnapshotToLive(snap, liveModified)
	if !diff2.HasDeltas {
		t.Fatalf("expected deltas detected")
	}

	if len(diff2.Deltas) != 3 { // A (modified), MX (removed), TXT (added)
		t.Errorf("expected 3 deltas, got %d", len(diff2.Deltas))
	}
}
