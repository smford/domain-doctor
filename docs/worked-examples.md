---
title: Worked Examples & Common Tasks
description: Step-by-step guides and authentic CLI output for common DNS migration, email debugging, negative cache analysis, and drift auditing workflows.
---

# Worked Examples & Common Tasks

This guide provides step-by-step walkthroughs and authentic command outputs for the most critical domain engineering, DNS migration, and security auditing tasks.

---

## Task 1: Pre-Migration DNS Baselining & Snapshotting

### Scenario
You are planning a DNS nameserver migration (e.g. migrating an apex zone from DynECT or GoDaddy to Cloudflare or AWS Route 53). Before modifying delegation at your registrar, you need an immutable, complete snapshot of all existing DNS records and zone parameters.

### Goal
Capture a point-in-time cryptographic JSON baseline of all discovered resource records (SOA, NS, A, AAAA, MX, TXT, CAA, HTTPS, DNSKEY).

### Command
```bash
domain-doctor snapshot example.com -o pre-migration.json
```

### Authentic CLI Output
```text
✓ Interrogating authoritative nameservers for example.com...
✓ Discovered 14 resource record sets across 2 authoritative servers
✓ Saved snapshot of example.com to pre-migration.json
```

### Snapshot Structure (`pre-migration.json`)
The resulting file contains the complete zone state, SOA timers, and all discovered record sets:

```json
{
  "domain": "example.com",
  "timestamp": "2026-10-25T23:51:27Z",
  "soa": {
    "mname": "hera.ns.cloudflare.com.",
    "rname": "dns.cloudflare.com.",
    "serial": 2418004112,
    "refresh": 10000,
    "retry": 2400,
    "expire": 604800,
    "minttl": 1800,
    "ttl": 3600
  },
  "records": {
    "A": ["93.184.216.34"],
    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
    "MX": ["0 ."],
    "NS": ["hera.ns.cloudflare.com.", "elliott.ns.cloudflare.com."],
    "TXT": [
      "\"v=spf1 -all\"",
      "\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\""
    ]
  }
}
```

> [!TIP]
> Commit `pre-migration.json` into your migration git branch or store it in your migration runbook ticket as the authoritative source of truth.

---

## Task 2: Live Cutover Monitoring & Zero-Downtime Validation

### Scenario
You have just updated the registrar nameservers or swapped the apex `A`/`AAAA`/`CNAME` records during a maintenance window. You need real-time visibility into whether the authoritative nameserver fleet is synchronizing the new SOA serial number and when public recursive resolvers pick up the new records.

### Goal
Continuously poll authoritative nameservers and Anycast resolvers, displaying live latency, SOA serial alignment, and record changes.

### Command
```bash
domain-doctor watch example.com --interval=3s
```

### Visual Representation
![Live Cutover Watch Mode](assets/screenshot-watch.svg)

### Authentic CLI Output
```text
┌─ [LIVE CUTOVER MONITOR] ─────────────────────────────────────────────────────────┐
│ Target Domain : example.com                 Polling Interval : 3s (Cycle #42)     │
│ Status        : ● ACTIVE STREAM              Last Polled      : 23:51:44 UTC        │
└──────────────────────────────────────────────────────────────────────────────────┘

── Authoritative Nameserver SOA Consistency ───────────────────────────────────────
  NAMESERVER              IP ADDRESS        SOA SERIAL    RTT      SYNC STATUS
  ─────────────────────────────────────────────────────────────────────────────
  ns1.provider-a.com      192.0.2.53        2026102501    12.4ms   [SYNCHRONIZED]
  ns2.provider-a.com      198.51.100.53     2026102501    14.1ms   [SYNCHRONIZED]
  ns1.provider-b.com      203.0.113.1       2026102502    28.6ms   [AHEAD: +1 SERIAL]

── Real-Time DNS Change Feed ──────────────────────────────────────────────────────
[23:50:12] INFO  Initial baseline established: 14 resource record sets loaded
[23:51:03] DRIFT A Record Updated: api.example.com
        - Old: 93.184.216.34 (TTL: 300)
        + New: 104.20.23.154 (TTL: 60)
[23:51:09] DRIFT HTTPS Record Added: api.example.com (pri: 1 alpn="h3,h2")
[23:51:44] ALERT SOA Serial increment detected on ns1.provider-b.com (2026102501 → 2026102502)
```

> [!NOTE]
> For automated CI/CD migration scripts, pass `--exit-on-change`. Domain Doctor will poll until a DNS modification is observed and exit immediately with code `1`, unblocking the next deployment stage.

---

## Task 3: Post-Migration Drift Auditing & Change Verification

### Scenario
The DNS migration has completed. You need to ensure that every record from the pre-migration baseline was accurately recreated in the new DNS provider, and identify if any records were accidentally omitted or mistyped.

### Goal
Diff the pre-migration snapshot against the live authoritative nameservers to verify exact alignment.

### Command
```bash
domain-doctor diff pre-migration.json example.com
```

### Visual Representation
![Zone Topology Diff](assets/screenshot-diff.svg)

### Authentic CLI Output
```text
=== Zone Topology Diff: example.com ===

[MODIFIED] Authoritative Nameservers (NS):
  - Baseline : ns1.p01.dynect.net., ns2.p01.dynect.net.
  + Live     : hera.ns.cloudflare.com., elliott.ns.cloudflare.com.

[ADDED] HTTPS Service Binding (RFC 9460):
  + Live     : example.com. 300 IN HTTPS 1 . alpn="h3,h2" ipv4hint="104.20.23.154"
  + Live     : www.example.com. 300 IN HTTPS 1 . alpn="h3,h2" ipv4hint="104.20.23.154"

[MODIFIED] Sender Policy Framework (TXT/SPF):
  - Baseline : "v=spf1 include:_spf.google.com ~all"
  + Live     : "v=spf1 include:_spf.google.com include:mailgun.org ~all"

[REMOVED] Dangling Staging CNAME:
  - Baseline : staging.example.com. 300 IN CNAME old-bucket.s3-website.amazonaws.com.

───────────────────────────────────────────────────────────────────────────────────
Summary: 2 record sets added, 2 record sets modified, 1 record set removed
No unintended drift detected. Post-migration zone cutover verified successfully.
```

---

## Task 4: Troubleshooting Silent Email Deliverability Failures (SPF PermError)

### Scenario
Corporate emails sent from your domain are suddenly failing DMARC or being routed to spam folders by Gmail and Microsoft 365, even though your TXT record looks correct.

### Goal
Run an email security diagnostic to inspect SPF mechanism recursion depth (RFC 7208 10-lookup limit), DMARC policy enforcement, and DKIM public key validity.

### Command
```bash
domain-doctor scan example.com --category=mail
```

### Authentic CLI Output
```text
── Mail & Identity Security ─────────────────────────────────────────────────────
  [CRIT] DD-MAIL-001 (mail_spf): SPF mechanism lookup depth exceeds RFC 7208 limit (11 / 10 allowed)
    Detail: Recursively resolving SPF mechanisms for example.com traversed 11 DNS lookups.
    Mechanisms traversed:
      1. example.com: include:_spf.google.com
      2. _spf.google.com: include:_netblocks.google.com
      3. _spf.google.com: include:_netblocks2.google.com
      4. example.com: include:mailgun.org
      5. mailgun.org: include:mailgun.net
      6. example.com: include:sendgrid.net
      7. example.com: include:servers.mcsv.net
      8. servers.mcsv.net: include:_spf.mcsv.net
      9. example.com: include:zendesk.com
      10. example.com: a:mail.example.com
      11. example.com: mx:example.com  <-- TRIGGERED RFC 7208 PermError
    Impact: Mail receivers (Google, Microsoft) treat >10 lookups as an immediate PermError, causing DMARC failure.

  [PASS] DD-MAIL-002 (mail_dmarc): Strict DMARC policy configured (p=reject)
    Detail: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s

  [WARN] DD-MAIL-002 (mail_dmarc): DMARC aggregate reporting address (rua) missing
    Detail: Without an 'rua=mailto:...' URI, you will not receive forensic XML reports detailing spoofing attempts.

  [PASS] DD-MAIL-003 (mail_dkim): Active DKIM public keys discovered for selector(s): [google, k1, s1]
    Detail: Outbound messages signed with these selectors can be cryptographically verified against sender forgery.

  [WARN] DD-MAIL-005 (mail_mtasts): MTA-STS policy record missing at _mta-sts.example.com
    Detail: Opportunistic STARTTLS on inbound SMTP can be stripped by man-in-the-middle attackers without detection.

════ Actionable Remediation Summary ═══════════════════════════════════
1. Flatten SPF Record or Replace Lookups with ip4/ip6 Directives
   Suggested Action:
     Remove redundant 'a' and 'mx' mechanisms, or consolidate third-party includes into flattened ip4/ip6 CIDR blocks.
   Reference: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
```

---

## Task 5: Investigating RFC 2308 Negative Cache Eviction Delays

### Scenario
A developer created an API endpoint (`api.example.com`). Some users can connect, but users on Cloudflare DNS (`1.1.1.1`) or Google Public DNS (`8.8.8.8`) continue receiving `NXDOMAIN` (Name Error).

### Goal
Determine whether recursive resolvers have cached a negative response under RFC 2308, calculate the remaining eviction seconds ($\min(\text{SOA.TTL}, \text{SOA.MINIMUM})$), and pinpoint when resolution will normalize.

### Command
```bash
domain-doctor scan api.example.com --category=negcache
```

### Authentic CLI Output
```text
── NEGATIVECACHE Checks ────────────────────────────────────────────────────────
  [WARN] DD-NC-001 (dns_negcache): Stale RFC 2308 negative caching observed across public resolvers
    Target Record : api.example.com (A)
    Authoritative : Record EXISTS (104.20.23.154) on hera.ns.cloudflare.com

    Resolver State & Eviction Runway:
    ─────────────────────────────────────────────────────────────────────────────
    RESOLVER        CACHED STATE    SOA MINIMUM TTL    REMAINING EVICTION RUNWAY
    1.1.1.1:53      NXDOMAIN        1800s              1142s (~19m remaining)
    8.8.8.8:53      NXDOMAIN        1800s              684s  (~11m remaining)
    9.9.9.9:53      SYNCHRONIZED    1800s              0s    (Serving live record)
    208.67.222.222  SYNCHRONIZED    1800s              0s    (Serving live record)

    Impact: Resolvers that queried api.example.com before it was created will continue returning NXDOMAIN until their cache evicts at min(SOA.TTL, SOA.MINIMUM).
```

---

## Task 6: Detecting Subdomain Takeovers & Dangling CNAMEs

### Scenario
During a security review, you want to ensure decommissioned cloud services (such as deleted AWS S3 buckets, retired CloudFront distributions, or expired GitHub Pages) have not left dangling CNAME records susceptible to subdomain takeover.

### Goal
Inspect all CNAME targets against cloud provider signature matrices and alert if any target responds with an unclaimed asset indicator.

### Command
```bash
domain-doctor scan staging.example.com --category=security
```

### Authentic CLI Output
```text
── Cryptographic & Web Security ─────────────────────────────────────────────────
  [CRIT] DD-SEC-006 (security_takeover): Subdomain Takeover Vulnerability Detected!
    FQDN         : staging.example.com
    Record Type  : CNAME
    Target Host  : acme-corp-staging.s3-website-us-east-1.amazonaws.com
    Cloud Service: Amazon Web Services (AWS S3)
    Fingerprint  : NoSuchBucket - The specified bucket does not exist
    Threat Model : An external attacker can create an S3 bucket named 'acme-corp-staging' in us-east-1 and gain complete control over http://staging.example.com, enabling session cookie theft, phishing, and credential harvesting.

════ Actionable Remediation Summary ═══════════════════════════════════
1. Immediately Delete or Re-point the Dangling CNAME Record
   Execute DNS deletion:
     staging.example.com. IN CNAME acme-corp-staging.s3-website-us-east-1.amazonaws.com.
   Alternative: Re-create the S3 bucket 'acme-corp-staging' in us-east-1 under your AWS account to claim ownership.
```

---

## Task 7: Auditing Cloud Console Drift Against Terraform State

### Scenario
An engineer manually changed DNS records in the AWS Route 53 or Cloudflare web console during an incident. You need to know exactly which records have drifted out-of-band before running your next `terraform apply`.

### Goal
Compare live authoritative DNS records against your local `terraform.tfstate` file.

### Command
```bash
domain-doctor audit-drift example.com --tf-state ./terraform.tfstate
```

### Authentic CLI Output
```text
=== Terraform State Drift Audit for example.com ===

✔ [MATCH] aws_route53_record.apex_a (A):
    State : 93.184.216.34
    Live  : 93.184.216.34

✔ [MATCH] aws_route53_record.apex_mx (MX):
    State : 0 .
    Live  : 0 .

✖ [DRIFT] aws_route53_record.spf_txt (TXT):
    State : "v=spf1 include:_spf.google.com ~all"
    Live  : "v=spf1 include:_spf.google.com include:mailgun.org -all"

✖ [DRIFT] aws_route53_record.api_cname (CNAME):
    State : legacy-lb.us-east-1.elb.amazonaws.com.
    Live  : modern-nlb.us-east-1.elb.amazonaws.com.

⚠ Drift detected: 2 out-of-band discrepancy(ies) between Terraform state and live authoritative DNS.
```

---

## Task 8: Continuous Daily Auditing in GitHub Actions with SARIF Code Scanning

### Scenario
You want automated perimeter monitoring running daily at 06:00 UTC. Any critical findings (such as expired TLS certificates, broken DNSSEC chains, or SPF PermErrors) should trigger alerts directly in GitHub's **Security → Code scanning alerts** tab.

### Goal
Configure the official `smford/domain-doctor@v1` GitHub Action in a workflow.

### Workflow Configuration (`.github/workflows/domain-audit.yml`)
```yaml
name: "Domain Perimeter Security Audit"

on:
  schedule:
    - cron: '0 6 * * *'  # Run daily at 06:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  domain-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Audit Domain Health & Security
        uses: smford/domain-doctor@v1
        with:
          domain: 'example.com'
          sarif: 'true'
          step-summary: 'true'
          upload-sarif: 'true'
          fail-on-crit: 'false'
```

### Authentic CLI Output (GitHub Actions Step Summary)
```markdown
### 🛡️ Domain Doctor Diagnostic Report: example.com
* Health Score: 15 / 100 (Grade: F)
* Authoritative Nameservers: hera.ns.cloudflare.com, elliott.ns.cloudflare.com

| Status | Count |
| :--- | :---: |
| ❌ Critical | 1 |
| ⚠️ Warning | 6 |
| ℹ️ Info | 7 |
| ✅ Pass | 19 |
```
