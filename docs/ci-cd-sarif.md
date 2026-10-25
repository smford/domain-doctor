---
title: CI/CD & SARIF Integration
description: Continuous domain auditing using GitHub Actions, SARIF v2.1.0 output, and GitHub Security Code Scanning integration.
---

# Continuous CI/CD Auditing & SARIF Integration

Domain Doctor can run automatically in your CI/CD pipelines to monitor domain health, catch DNS misconfigurations during pull requests, and report security vulnerabilities directly into **GitHub Security Code Scanning**.

---

## 🛡️ What is SARIF?

**SARIF (Static Analysis Results Interchange Format)** is an OASIS standard JSON format used by GitHub Advanced Security, GitLab, and other security platforms to display vulnerabilities, configuration drift, and static analysis findings directly in the repository UI.

When you run `domain-doctor scan <domain> --sarif`, it generates a fully compliant **SARIF v2.1.0** report including:
- Permanent Rule IDs (e.g. `DD-MAIL-001`, `DD-SEC-006`).
- Rule metadata: Name, Full Description, Help Markdown, RFC references.
- Precise severity mapping (`error` for `CRIT`, `warning` for `WARN`, `note` for `INFO`).
- Physical and logical URI locations bound to the inspected domain.

---

## ⏰ Automated Daily Cron Workflow

Add this GitHub Actions workflow to run a daily health audit against your production domains and inject findings into your repository's **Security > Code scanning alerts** tab.

Create `.github/workflows/domain-audit-cron.yml`:

```yaml
name: "Continuous Domain Health & Security Audit"

on:
  schedule:
    # Run every morning at 06:00 UTC
    - cron: '0 6 * * *'
  workflow_dispatch:
    inputs:
      target_domain:
        description: 'Domain to audit'
        required: false
        default: 'example.com'

permissions:
  contents: read
  security-events: write # Required for uploading SARIF results

concurrency:
  group: domain-audit-${{ github.ref }}
  cancel-in-progress: true

jobs:
  audit:
    name: "Audit Domain Security & DNS"
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Domain Doctor
        run: |
          VERSION="v0.2.0"
          curl -sSL "https://github.com/smford/domain-doctor/releases/download/${VERSION}/domain-doctor_Linux_x86_64.tar.gz" -o domain-doctor.tar.gz
          tar -xzf domain-doctor.tar.gz domain-doctor
          sudo mv domain-doctor /usr/local/bin/

      - name: Execute Authoritative Scan & Generate SARIF
        run: |
          TARGET="${{ github.event.inputs.target_domain || 'example.com' }}"
          echo "Auditing domain: $TARGET"

          # Run scan with SARIF output; continue-on-error so SARIF is uploaded even if CRIT is found
          domain-doctor scan "$TARGET" --sarif > results.sarif || true

      - name: Upload Scan Results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: domain-doctor
```

---

## 🚦 Pull Request Quality Gate Workflow

Prevent pull requests from merging if a DNS change or zone file update introduces critical errors (such as SPF PermError or missing DNSSEC signatures).

Create `.github/workflows/domain-pr-gate.yml`:

```yaml
name: "DNS Configuration Quality Gate"

on:
  pull_request:
    branches: [main]
    paths:
      - 'zones/**'
      - 'terraform/**'
      - '.domain-doctor.yaml'

permissions:
  contents: read

jobs:
  lint-and-validate:
    name: "Validate Zone Files & Staging Domain"
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Domain Doctor
        run: |
          VERSION="v0.2.0"
          curl -sSL "https://github.com/smford/domain-doctor/releases/download/${VERSION}/domain-doctor_Linux_x86_64.tar.gz" -o domain-doctor.tar.gz
          tar -xzf domain-doctor.tar.gz domain-doctor
          sudo mv domain-doctor /usr/local/bin/

      - name: Static Lint Zone Files
        run: |
          for zone in zones/*.zone; do
            if [ -f "$zone" ]; then
              echo "Linting $zone..."
              domain-doctor lint "$zone"
            fi
          done

      - name: Audit Staging Domain Health
        run: |
          # Exit code 1 on any CRIT finding fails the PR build
          domain-doctor scan staging.example.com --summary
```

---

## 🔍 Viewing Results in GitHub

Once SARIF results are uploaded:
1. Navigate to your GitHub repository.
2. Click on the **Security** tab.
3. Select **Code scanning** in the left sidebar.
4. You will see alerts categorized under `domain-doctor`, complete with rule descriptions, RFC references, and remediation guidance:

```
[Critical] SPF mechanism lookup depth exceeds RFC 7208 limit (DD-MAIL-001)
example.com: SPF record contains 11 DNS mechanisms (limit is 10). Triggers RFC 7208 PermError.
```
