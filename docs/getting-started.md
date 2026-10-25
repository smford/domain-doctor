---
title: Getting Started
description: Installation guide, signature verification, and basic usage tutorial for Domain Doctor.
---

# Getting Started with Domain Doctor

This guide walks you through installing `domain-doctor`, verifying cryptographic release signatures, running your first authoritative diagnostic audit, and setting up shell autocompletion.

---

## 📦 Installation Options

Choose the installation method best suited to your platform and environment.

### 1. Homebrew (macOS & Linux)

The easiest method for macOS and Linux workstations is via Homebrew:

```bash
# Tap the official repository
brew tap smford/tap

# Install domain-doctor
brew install domain-doctor
```

To upgrade to the latest release in the future:
```bash
brew update && brew upgrade domain-doctor
```

---

### 2. Docker Container

Domain Doctor is published as a hardened, scratch-based multi-arch container image (`linux/amd64` and `linux/arm64`) to the GitHub Container Registry (`ghcr.io`):

```bash
# Pull the latest container image
docker pull ghcr.io/smford/domain-doctor:latest

# Run an authoritative scan
docker run --rm ghcr.io/smford/domain-doctor:latest scan example.com
```

To run with a custom configuration file mounted into the container:
```bash
docker run --rm -v $(pwd)/.domain-doctor.yaml:/root/.domain-doctor.yaml \
  ghcr.io/smford/domain-doctor:latest scan example.com
```

---

### 3. Pre-Compiled Static Binaries

Hermetic, statically-linked binaries (`CGO_ENABLED=0`) are built and published for each release:

| Platform | Architecture | Binary Archive |
| :--- | :--- | :--- |
| **macOS** | Apple Silicon (`arm64`) | `domain-doctor_Darwin_arm64.tar.gz` |
| **macOS** | Intel (`x86_64`) | `domain-doctor_Darwin_x86_64.tar.gz` |
| **Linux** | 64-bit ARM (`arm64`) | `domain-doctor_Linux_arm64.tar.gz` |
| **Linux** | 64-bit x86 (`x86_64`) | `domain-doctor_Linux_x86_64.tar.gz` |

Download pre-compiled binaries from the [GitHub Releases](https://github.com/smford/domain-doctor/releases) page.

Example installation using `curl` and `tar`:
```bash
# Download latest Linux x86_64 release (replace version as needed)
VERSION="v0.2.0"
curl -sSL "https://github.com/smford/domain-doctor/releases/download/${VERSION}/domain-doctor_Linux_x86_64.tar.gz" -o domain-doctor.tar.gz

# Extract binary
tar -xzf domain-doctor.tar.gz domain-doctor

# Move to system PATH
sudo mv domain-doctor /usr/local/bin/
```

---

### 4. Go Install

If you have Go 1.22+ installed, you can compile and install Domain Doctor directly from source:

```bash
go install github.com/smford/domain-doctor/cmd/domain-doctor@latest
```

Ensure `$GOPATH/bin` or `$HOME/go/bin` is in your `$PATH`.

---

## 🔒 Cryptographic Signature Verification (Cosign)

All official release artifacts and container images are cryptographically signed using **Sigstore Cosign v4 Keyless Signatures** bound to GitHub Actions OIDC identity.

### Verifying Release Archives

Every release includes a `checksums.txt` file and an associated Cosign bundle `checksums.txt.bundle`:

```bash
# 1. Download checksums and bundle
curl -sSLO https://github.com/smford/domain-doctor/releases/download/v0.2.0/checksums.txt
curl -sSLO https://github.com/smford/domain-doctor/releases/download/v0.2.0/checksums.txt.bundle

# 2. Verify Cosign keyless signature
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp "https://github.com/smford/domain-doctor/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

# 3. Verify SHA256 of downloaded archive
sha256sum --check checksums.txt --ignore-missing
```

### Verifying Container Images

Verify container images directly against the GitHub Actions workflow identity:

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/smford/domain-doctor/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/smford/domain-doctor:latest
```

---

## ⏱️ Your First Authoritative Scan

Run an end-to-end diagnostic scan against any public domain:

```bash
domain-doctor scan example.com
```

### What Happens During a Scan?
1. **Delegation Discovery**: Queries root and TLD nameservers to determine authoritative nameservers for `example.com`.
2. **Authoritative Interrogation**: Connects to the authoritative nameservers directly over raw UDP/TCP (Port 53) to fetch ground truth records (SOA, NS, A, AAAA, MX, TXT, CAA, DNSKEY, DS).
3. **Recursive Cross-Referencing**: Simultaneously queries public Anycast resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`) to detect negative caching divergence, propagation delays, and DNSSEC validation errors.
4. **Diagnostic Rules Execution**: Runs all 30 checks in parallel across DNS, Mail, Security, Resilience, Registration, and Threat categories.
5. **Output Presentation**: Renders findings with colored status badges (`PASS`, `INFO`, `WARN`, `CRIT`, `SKIP`).

---

## 📊 Controlling Output Formats

Domain Doctor supports multiple output formats tailored for human inspection or automated ingestion:

### 1. Executive Summary Table (`--summary`)
Prints a clean tabular summary grouping checks by category with overall health score:

```bash
domain-doctor scan example.com --summary
```

### 2. Formatted Markdown Report (`--report=markdown`)
Generates a complete executive and engineering report with threat models and RFC references:

```bash
domain-doctor scan example.com --report=markdown > report.md
```

### 3. Machine-Readable JSON (`--output=json`)
Outputs complete structured diagnostic data for custom scripts or data pipelines:

```bash
domain-doctor scan example.com --output=json | jq '.checks[] | select(.status == "CRIT")'
```

### 4. SARIF v2.1.0 (`--sarif`)
Outputs OASIS Standard SARIF format for integration into GitHub Advanced Security Code Scanning:

```bash
domain-doctor scan example.com --sarif > results.sarif
```

---

## 🚦 Exit Codes Reference

Domain Doctor adheres to UNIX conventions for automation and CI/CD pipelines:

| Exit Code | Meaning | Condition |
| :---: | :--- | :--- |
| `0` | **Success / Healthy** | All checks passed or produced only `INFO` / `WARN` findings. |
| `1` | **Failure / Critical** | One or more executed checks returned `CRIT` status. |
| `2` | **Usage / System Error** | Invalid flags, unresolvable domain, or configuration file parsing error. |

---

## 💻 Shell Auto-Completion

Generate shell completion scripts to enable tab-completion for all commands and flags:

::: tabs
@tab Bash
```bash
# Add to ~/.bashrc
source <(domain-doctor completion bash)
```
@tab Zsh
```bash
# Add to ~/.zshrc
source <(domain-doctor completion zsh)
```
@tab Fish
```bash
# Add to ~/.config/fish/config.fish
domain-doctor completion fish | source
```
:::
