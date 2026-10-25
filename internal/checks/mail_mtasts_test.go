package checks

import (
	"testing"
)

func TestParseMTASTSPolicy(t *testing.T) {
	policyText := `version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 604800
`
	mode, mxList, maxAge := parseMTASTSPolicy(policyText)
	if mode != "enforce" {
		t.Errorf("expected mode 'enforce', got '%s'", mode)
	}
	if len(mxList) != 2 {
		t.Fatalf("expected 2 mx entries, got %d", len(mxList))
	}
	if mxList[0] != "mail.example.com" || mxList[1] != "*.example.com" {
		t.Errorf("unexpected mxList: %v", mxList)
	}
	if maxAge != "604800" {
		t.Errorf("expected maxAge '604800', got '%s'", maxAge)
	}
}
