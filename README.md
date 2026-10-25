# domain-doctor

[![CI](https://github.com/smford/domain-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/smford/domain-doctor/actions/workflows/ci.yml)
[![Release](https://github.com/smford/domain-doctor/actions/workflows/release.yml/badge.svg)](https://github.com/smford/domain-doctor/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/smford/domain-doctor/badge)](https://scorecard.dev/viewer/?uri=github.com/smford/domain-doctor)
[![Docs](https://img.shields.io/badge/docs-website-blue.svg)](http://stephenford.org/domain-doctor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Comprehensive domain health, DNS diagnostic, and TLS autopsy CLI tool.**

---

## 🚀 Features

- **DNS Diagnostics**: Deep analysis across nameservers, propagation, record discrepancies, and authoritative SOA validation.
- **TLS/SSL Inspection**: Certificate chain verification, cipher suite evaluation, and expiry alerts.
- **Zero-Trust Security**: Pre-commit linting, static analysis, SAST with CodeQL & Semgrep, DAST with OWASP ZAP, and OpenSSF Scorecard auditing.
- **Static Multi-Platform Binaries**: Compiled with `CGO_ENABLED=0` for macOS and Linux (arm64 & amd64).

---

## 📦 Installation

### Homebrew (macOS & Linux)

```bash
brew tap smford/tap
brew install domain-doctor
```

### Docker Container

```bash
docker pull ghcr.io/smford/domain-doctor:latest
docker run -p 8080:8080 ghcr.io/smford/domain-doctor:latest
```

### Go Install

```bash
go install github.com/smford/domain-doctor/cmd/domain-doctor@latest
```

---

## 🛠 Usage

```bash
# Check version information
domain-doctor --version

# Run health daemon
domain-doctor -port 8080
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
