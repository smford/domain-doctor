---
title: Configuration Guide
description: Complete specification of .domain-doctor.yaml configuration file, rule filtering, severity overrides, and parameter tuning.
---

# Configuration Guide

Domain Doctor can be configured via a YAML configuration file (`.domain-doctor.yaml`) to customize scan execution, suppress noisy checks, override default rule severities, and fine-tune threshold parameters.

---

## Configuration Discovery Order

Domain Doctor automatically searches for configuration files in the following hierarchical order:

1. Path explicitly provided via `--config <path>` flag.
2. Current working directory: `./.domain-doctor.yaml`
3. Current working directory: `./domain-doctor.yaml`
4. User configuration directory: `$HOME/.config/domain-doctor/config.yaml`
5. Global system configuration: `/etc/domain-doctor/config.yaml`

If no configuration file is found, Domain Doctor executes with default production parameters.

---

## Configuration Schema

The configuration file is organized into three main sections:

- **`global`**: Runtime network and presentation options.
- **`rules`**: Rule filtering and severity override mappings.
- **`checks`**: Tuneable thresholds for individual diagnostic rules.

---

## 1. Global Settings (`global`)

```yaml
global:
  # Default recursive resolvers used for cross-reference lookups
  resolvers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
    - "9.9.9.9:53"

  # If true, queries nameservers directly and bypasses recursive resolvers
  authoritative_only: false

  # Per-request network timeout (e.g. 5s, 10s, 1m)
  timeout: "10s"

  # Number of UDP query retries before marking an endpoint unreachable
  retries: 2

  # Whether to display SKIPPED checks in output
  show_skipped: false
```

---

## 2. Rule Filters & Severity Overrides (`rules`)

You can enable or disable checks, or override their default severity level, using either the permanent rule ID (e.g. `DD-MAIL-006`) or the check's short name (e.g. `mail_bimi`).

```yaml
rules:
  # Explicitly enable only selected checks. If empty, all checks are enabled by default.
  enable: []

  # Checks to disable and skip during scan execution
  disable:
    - "DD-MAIL-006"        # Disable BIMI check (not applicable for all domains)
    - "threat_homograph"   # Disable homoglyph permutation generation for speed

  # Override default rule severities
  # Permitted values: CRIT, WARN, INFO, PASS, SKIP
  severity_override:
    "DD-SEC-004": "CRIT"   # Escalate missing CAA record to CRIT
    "DD-MAIL-004": "INFO"  # Downgrade STARTTLS warning to INFO
    "DD-DNS-004": "PASS"   # Treat HTTPS/SVCB presence as standard pass
```

---

## 3. Check-Specific Tuneables (`checks`)

Fine-tune internal thresholds and behavior for individual rules:

```yaml
checks:
  # DD-DNS-001: Minimum required authoritative nameservers (RFC 2182 recommends >= 2)
  min_nameservers: 2

  # DD-REG-002: Minimum remaining domain registration days before warning
  min_registration_days: 30

  # DD-SEC-005: Minimum remaining TLS certificate validity runway days
  min_cert_days: 14

  # DD-MAIL-003: Common DKIM selectors to probe during mail audit
  dkim_selectors:
    - "default"
    - "google"
    - "k1"
    - "s1"
    - "s2"
    - "mail"
    - "cm"
    - "pic"

  # DD-SEC-010: Cookie names considered sensitive that require Secure, HttpOnly, and SameSite
  sensitive_cookies:
    - "session"
    - "token"
    - "jwt"
    - "auth"
    - "id"
    - "sid"
    - "remember"
    - "csrf"
    - "xsrf"

  # DD-DNS-005: Explicitly allow wildcard DNS records without emitting WARN
  allow_wildcards: false

  # DD-SEC-008: TCP ports to probe when testing CDN direct-to-origin bypass
  cdn_origin_ports:
    - 80
    - 443
    - 8080
    - 8443
```

---

## Full Annotated `.domain-doctor.yaml` Example

Save this template to `.domain-doctor.yaml` in your project root or home directory:

```yaml
# .domain-doctor.yaml - Domain Doctor Configuration Specification

global:
  resolvers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
    - "9.9.9.9:53"
  authoritative_only: false
  timeout: "10s"
  retries: 2
  show_skipped: false

rules:
  # If specified, only run these rules. Leave empty to run all.
  enable: []

  # Rules to skip completely
  disable:
    - "DD-MAIL-006"        # mail_bimi
    - "DD-THR-002"         # threat_homograph

  # Customize severity levels to fit your organizational risk posture
  severity_override:
    "DD-SEC-004": "CRIT"   # Escalate missing CAA from WARN to CRIT
    "DD-DNS-001": "CRIT"   # Nameserver redundancy failure is always CRIT
    "DD-RES-001": "CRIT"   # Single BGP ASN dependency is CRIT

checks:
  min_nameservers: 2
  min_registration_days: 45
  min_cert_days: 21
  dkim_selectors:
    - "default"
    - "google"
    - "k1"
    - "s1"
    - "mail"
  sensitive_cookies:
    - "session"
    - "auth"
    - "token"
    - "jwt"
    - "sid"
    - "csrf"
  allow_wildcards: false
  cdn_origin_ports:
    - 80
    - 443
```
