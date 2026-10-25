package checks

import (
	"strings"
	"testing"
)

func TestTeamCymruParsing(t *testing.T) {
	// Sample TXT response from Team Cymru: "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
	sampleTXT := "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
	fields := strings.Split(sampleTXT, "|")
	if len(fields) < 5 {
		t.Fatalf("expected at least 5 fields from Cymru response, got %d", len(fields))
	}

	asn := strings.TrimSpace(fields[0])
	if asn != "15169" {
		t.Errorf("expected ASN 15169, got '%s'", asn)
	}

	prefix := strings.TrimSpace(fields[1])
	if prefix != "8.8.8.0/24" {
		t.Errorf("expected prefix 8.8.8.0/24, got '%s'", prefix)
	}

	country := strings.TrimSpace(fields[2])
	if country != "US" {
		t.Errorf("expected country US, got '%s'", country)
	}
}
