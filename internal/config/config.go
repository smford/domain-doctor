package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RuleConfig struct {
	Enable            []string          `yaml:"enable"`
	Disable           []string          `yaml:"disable"`
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
}

type SettingsConfig struct {
	Timeout             string   `yaml:"timeout"`
	Resolver            string   `yaml:"resolver"`
	CustomDKIMSelectors []string `yaml:"custom_dkim_selectors"`
}

type Config struct {
	Version  int            `yaml:"version"`
	Rules    RuleConfig     `yaml:"rules"`
	Settings SettingsConfig `yaml:"settings"`
}

func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Rules: RuleConfig{
			Enable:            []string{"*"},
			Disable:           []string{},
			SeverityOverrides: make(map[string]string),
		},
		Settings: SettingsConfig{
			Timeout:  "25s",
			Resolver: "",
		},
	}
}

// Load attempts to load a configuration file from the specified path,
// or automatically looks for .domain-doctor.yaml / .domain-doctor.yml in current working directory.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	targetPath := path
	if targetPath == "" {
		candidates := []string{".domain-doctor.yaml", ".domain-doctor.yml"}
		for _, cand := range candidates {
			if _, err := os.Stat(cand); err == nil {
				targetPath = cand
				break
			}
		}
	}

	if targetPath == "" {
		// No config found, return default
		return cfg, nil
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", targetPath, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config '%s': %w", targetPath, err)
	}

	return cfg, nil
}

// IsRuleEnabled checks if a given rule ID and category is enabled by configuration
func (c *Config) IsRuleEnabled(ruleID string, category string) bool {
	// First check explicit disable list
	for _, dis := range c.Rules.Disable {
		if matchRulePattern(dis, ruleID, category) {
			return false
		}
	}

	// Then check enable list
	if len(c.Rules.Enable) == 0 {
		return true
	}
	for _, en := range c.Rules.Enable {
		if en == "*" || matchRulePattern(en, ruleID, category) {
			return true
		}
	}
	return false
}

func matchRulePattern(pattern, ruleID, category string) bool {
	p := strings.ToUpper(strings.TrimSpace(pattern))
	r := strings.ToUpper(strings.TrimSpace(ruleID))
	c := strings.ToUpper(strings.TrimSpace(category))

	if p == "*" || p == r || p == c {
		return true
	}
	if strings.HasSuffix(p, "*") {
		prefix := strings.TrimSuffix(p, "*")
		if strings.HasPrefix(r, prefix) || strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// ParseTimeout parses the configured timeout string, or returns fallback
func (c *Config) ParseTimeout(fallback time.Duration) time.Duration {
	if c.Settings.Timeout == "" {
		return fallback
	}
	d, err := time.ParseDuration(c.Settings.Timeout)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
