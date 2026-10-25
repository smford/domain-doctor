---
title: CLI Command Reference
description: Complete reference guide for all Domain Doctor CLI subcommands, options, and usage examples.
---

# CLI Command Reference

Domain Doctor provides a suite of 10 subcommands for inspecting, monitoring, linting, visualizing, and auditing domain and DNS infrastructures.

---

## Global Options

These flags apply to all commands that execute network lookups or rule evaluations:

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--config` | `string` | `""` | Path to custom YAML configuration file (e.g. `.domain-doctor.yaml`). |
| `--resolver` | `string` | `""` | Custom recursive DNS resolver address (e.g. `1.1.1.1:53` or `8.8.8.8`). |
| `--authoritative-only` | `bool` | `false` | Force queries directly to authoritative nameservers, bypassing recursive resolvers. |
| `--timeout` | `duration` | `10s` | Network timeout for individual DNS and TLS socket connections. |
| `--retries` | `int` | `2` | Number of UDP query retransmissions before treating a server as unresponsive. |
| `--show-skipped` | `bool` | `false` | Display skipped checks in terminal output and reports. |
| `-h`, `--help` | `bool` | `false` | Display contextual help and flag documentation. |

---

## 1. `domain-doctor scan`

Runs a full battery of authoritative and recursive diagnostic audits against a domain.

```bash
domain-doctor scan <domain> [flags]
```

### Flags

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--summary` | `bool` | `false` | Output high-level executive summary table grouped by category. |
| `--report` | `string` | `""` | Format for comprehensive diagnostic report (`markdown`, `json`, `text`). |
| `--sarif` | `bool` | `false` | Output findings in OASIS SARIF v2.1.0 JSON format for GitHub Security Scanning. |
| `--output` | `string` | `terminal` | Format for scan results (`terminal`, `json`, `yaml`). |

### Examples

```bash
# Standard interactive audit
domain-doctor scan example.com

# Authoritative-only inspection with 5-second timeout
domain-doctor scan example.com --authoritative-only --timeout=5s

# Generate SARIF report for GitHub Code Scanning
domain-doctor scan example.com --sarif > results.sarif

# Export JSON to filter with jq
domain-doctor scan example.com --output=json | jq '.checks[] | {id, status, message}'
```

---

## 2. `domain-doctor watch`

Continuously polls and monitors authoritative nameservers at a configurable cadence, highlighting record drift and TTL decrements in real-time.

```bash
domain-doctor watch <domain> [flags]
```

### Flags

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--interval` | `duration` | `30s` | Polling interval between diagnostic cycles (e.g. `10s`, `1m`). |
| `--exit-on-change` | `bool` | `false` | Automatically terminate with exit code `1` immediately upon detecting any record change. |

### Examples

```bash
# Monitor live zone transitions during a DNS migration
domain-doctor watch example.com --interval=10s

# CI/CD deployment verification: poll until DNS propagation finishes or fails
domain-doctor watch example.com --interval=5s --exit-on-change
```

---

## 3. `domain-doctor lint`

Performs offline, static linting and syntax validation against a raw BIND / RFC 1035 master zone file without making network requests.

```bash
domain-doctor lint <zone-file>
```

### Validations Performed
- RFC 1035 syntax and zone origin validation.
- Missing trailing dot detection in FQDN targets (`CNAME`, `MX`, `NS`).
- CNAME co-existence violations (RFC 2181 §10.1).
- Out-of-zone glue record sanity checks.
- Deprecated record types (`SPF`, `MD`, `MF`).

### Examples

```bash
# Lint a local zone file prior to DNS server reload
domain-doctor lint /etc/bind/zones/example.com.zone
```

---

## 4. `domain-doctor snapshot`

Interrogates authoritative nameservers and takes a point-in-time cryptographic JSON snapshot of all discovered DNS records and zone parameters.

```bash
domain-doctor snapshot <domain> [flags]
```

### Flags

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `-o`, `--output` | `string` | `""` | Output file path for snapshot JSON. If omitted, writes to stdout. |

### Examples

```bash
# Capture pre-migration baseline
domain-doctor snapshot example.com -o baseline.json

# Capture post-migration snapshot
domain-doctor snapshot example.com -o post-migration.json
```

---

## 5. `domain-doctor diff`

Compares two point-in-time snapshot files and produces a colored unified diff highlighting added, removed, or modified DNS records.

```bash
domain-doctor diff <snapshot-a.json> <snapshot-b.json> [flags]
```

### Flags

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--ignore-ttl` | `bool` | `false` | Ignore differences in record TTL values and focus solely on record data. |

### Examples

```bash
# Compare baseline vs post-migration state
domain-doctor diff baseline.json post-migration.json

# Compare ignoring normal TTL fluctuations
domain-doctor diff baseline.json post-migration.json --ignore-ttl
```

---

## 6. `domain-doctor diagram`

Generates an architecture diagram visualizing DNS delegation hierarchies, authoritative nameservers, MX mail routing, and CDN endpoints.

```bash
domain-doctor diagram <domain> [flags]
```

### Flags

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `-o`, `--output` | `string` | `""` | File path to write diagram output. |
| `--format` | `string` | `dot` | Output diagram format (`dot`, `svg`, `png`, `mermaid`). |

### Examples

```bash
# Generate Graphviz DOT graph
domain-doctor diagram example.com --format=dot -o architecture.dot

# Render directly to SVG (requires Graphviz 'dot' binary installed)
domain-doctor diagram example.com --format=svg -o architecture.svg
```

---

## 7. `domain-doctor export`

Exports the live authoritative DNS record set into various infrastructure-as-code and configuration formats.

```bash
domain-doctor export <domain> [flags]
```

### Flags

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--format` | `string` | `bind` | Export target format (`bind`, `terraform`, `json`, `yaml`). |
| `-o`, `--output` | `string` | `""` | Destination file path. If omitted, writes to stdout. |

### Examples

```bash
# Export live zone to standard BIND zone file format
domain-doctor export example.com --format=bind -o example.com.zone

# Generate Terraform AWS Route53 resource definitions
domain-doctor export example.com --format=terraform -o route53.tf
```

---

## 8. `domain-doctor audit-drift`

Compares live authoritative DNS state against a local Terraform state file (`terraform.tfstate`) to detect out-of-band changes made via web consoles.

```bash
domain-doctor audit-drift <domain> <state-file>
```

### Examples

```bash
# Audit terraform state drift
domain-doctor audit-drift example.com ./terraform.tfstate
```

---

## 9. `domain-doctor version`

Displays Domain Doctor build version, Git commit SHA, and Go runtime environment.

```bash
domain-doctor version
```

### Example Output

```
domain-doctor v0.2.0 (commit: fc66793, built: 2026-10-25T22:15:00Z, runtime: darwin/arm64)
```

---

## 10. `domain-doctor serve`

Launches a lightweight health check and readiness HTTP daemon for container orchestrators (e.g. Kubernetes, Nomad).

```bash
domain-doctor serve [flags]
```

### Flags

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--port` | `string` | `"8080"` | TCP port for HTTP server (endpoints: `/healthz`, `/livez`, `/readyz`). |

### Examples

```bash
# Start container liveness endpoint on port 8080
domain-doctor serve --port=8080
```
