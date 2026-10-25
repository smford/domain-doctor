package config

import (
	"testing"
	"time"
)

func TestConfigRuleFiltering(t *testing.T) {
	cfg := &Config{
		Version: 1,
		Rules: RuleConfig{
			Enable:  []string{"DD-DNS-*", "DD-MAIL-001", "Security"},
			Disable: []string{"DD-DNS-005"},
			SeverityOverrides: map[string]string{
				"DD-MAIL-001": "CRIT",
			},
		},
		Settings: SettingsConfig{
			Timeout: "45s",
		},
	}

	// DD-DNS-001 should be enabled (matches DD-DNS-*)
	if !cfg.IsRuleEnabled("DD-DNS-001", "DNS") {
		t.Errorf("expected DD-DNS-001 to be enabled")
	}

	// DD-DNS-005 should be disabled (in explicit disable list)
	if cfg.IsRuleEnabled("DD-DNS-005", "DNS") {
		t.Errorf("expected DD-DNS-005 to be disabled")
	}

	// DD-MAIL-001 should be enabled
	if !cfg.IsRuleEnabled("DD-MAIL-001", "Mail") {
		t.Errorf("expected DD-MAIL-001 to be enabled")
	}

	// DD-MAIL-002 should be disabled (not matched by enable list)
	if cfg.IsRuleEnabled("DD-MAIL-002", "Mail") {
		t.Errorf("expected DD-MAIL-002 to be disabled")
	}

	// Any Security check should be enabled (category match)
	if !cfg.IsRuleEnabled("DD-SEC-001", "Security") {
		t.Errorf("expected DD-SEC-001 to be enabled via Security category")
	}

	// Timeout parsing
	timeout := cfg.ParseTimeout(10 * time.Second)
	if timeout != 45*time.Second {
		t.Errorf("expected 45s timeout, got %v", timeout)
	}
}
