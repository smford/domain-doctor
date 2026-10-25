package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/smford/domain-doctor/internal/engine"
)

type RecordDelta struct {
	Type   string   `json:"type"`
	Status string   `json:"status"` // "ADDED", "REMOVED", "UNCHANGED"
	Old    []string `json:"old,omitempty"`
	New    []string `json:"new,omitempty"`
}

type DiffReport struct {
	Domain    string        `json:"domain"`
	HasDeltas bool          `json:"has_deltas"`
	Deltas    []RecordDelta `json:"deltas"`
}

func CompareSnapshotToLive(snap *engine.ZoneSnapshot, live *engine.DiagnosticReport) *DiffReport {
	diffReport := &DiffReport{
		Domain: live.Domain,
		Deltas: make([]RecordDelta, 0),
	}

	allTypes := make(map[string]bool)
	if snap.Records != nil {
		for t := range snap.Records {
			allTypes[t] = true
		}
	}
	if live.Records != nil {
		for t := range live.Records {
			allTypes[t] = true
		}
	}

	typesSorted := make([]string, 0, len(allTypes))
	for t := range allTypes {
		typesSorted = append(typesSorted, t)
	}
	sort.Strings(typesSorted)

	for _, rtype := range typesSorted {
		oldList := getNormalized(snap.Records, rtype)
		newList := getNormalized(live.Records, rtype)

		if strings.Join(oldList, "|") != strings.Join(newList, "|") {
			diffReport.HasDeltas = true
			status := "MODIFIED"
			if len(oldList) == 0 {
				status = "ADDED"
			} else if len(newList) == 0 {
				status = "REMOVED"
			}

			diffReport.Deltas = append(diffReport.Deltas, RecordDelta{
				Type:   rtype,
				Status: status,
				Old:    oldList,
				New:    newList,
			})
		}
	}

	return diffReport
}

func getNormalized(records map[string][]string, rtype string) []string {
	if records == nil {
		return []string{}
	}
	list, ok := records[rtype]
	if !ok {
		return []string{}
	}
	sorted := make([]string, len(list))
	copy(sorted, list)
	sort.Strings(sorted)
	return sorted
}

func (d *DiffReport) FormatTerminal() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== Zone Topology Diff: %s ===\n", d.Domain))
	if !d.HasDeltas {
		b.WriteString("✓ Zone records match snapshot exactly. No drift detected.\n")
		return b.String()
	}

	for _, delta := range d.Deltas {
		b.WriteString(fmt.Sprintf("\n[%s] %s Records:\n", delta.Status, delta.Type))
		if len(delta.Old) > 0 {
			b.WriteString(fmt.Sprintf("  - Snapshot: %s\n", strings.Join(delta.Old, ", ")))
		}
		if len(delta.New) > 0 {
			b.WriteString(fmt.Sprintf("  + Live:     %s\n", strings.Join(delta.New, ", ")))
		}
	}
	return b.String()
}
