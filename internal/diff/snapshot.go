package diff

import (
	"encoding/json"
	"os"
	"time"

	"github.com/smford/domain-doctor/internal/engine"
)

func CreateSnapshot(report *engine.DiagnosticReport) *engine.ZoneSnapshot {
	snap := &engine.ZoneSnapshot{
		Domain:    report.Domain,
		Timestamp: time.Now().UTC(),
		Records:   report.Records,
		Findings:  report.Findings,
	}
	return snap
}

func SaveSnapshot(snap *engine.ZoneSnapshot, filePath string) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

func LoadSnapshot(filePath string) (*engine.ZoneSnapshot, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var snap engine.ZoneSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
