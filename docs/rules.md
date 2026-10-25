# Domain Doctor Security & Diagnostic Rule Catalog

This catalog documents the complete battery of 30 diagnostic and security auditing rules implemented in `domain-doctor`. Each rule possesses a permanent, unique identifier formatted as `DD-<CATEGORY>-<NUMBER>`.

---

## Quick Reference Summary

| Rule ID | Category | Name | Default Severity | Standard / RFC |
| :--- | :--- | :--- | :--- | :--- |
| [`DD-DNS-001`](#dd-dns-001-authoritative-nameserver-redundancy) | DNS | `dns_delegation_count` | `CRIT` / `WARN` | RFC 1034 §4.1 / RFC 2182 |
| [`DD-DNS-002`](#dd-dns-002-authoritative-zone-transfer-axfr) | DNS | `dns_zone_transfer` | `CRIT` | RFC 5936 |
| [`DD-DNS-003`](#dd-dns-003-open-dns-recursion) | DNS | `dns_recursion` | `CRIT` | RFC 5358 |
| [`DD-DNS-004`](#dd-dns-004-https--svcb-service-binding) | DNS | `dns_https_svcb` | `INFO` | RFC 9460 |
| [`DD-DNS-005`](#dd-dns-005-wildcard-dns-scope) | DNS | `dns_wildcard` | `WARN` | RFC 4592 |
| [`DD-NC-001`](#dd-nc-001-rfc-2308-negative-cache-staleness) | NegativeCache | `dns_negcache` | `WARN` | RFC 2308 |
| [`DD-MAIL-001`](#dd-mail-001-spf-mechanism-lookup-depth) | Mail | `mail_spf` | `CRIT` | RFC 7208 §4.6.4 |
| [`DD-MAIL-002`](#dd-mail-002-dmarc-policy-enforcement) | Mail | `mail_dmarc` | `CRIT` | RFC 7489 |
| [`DD-MAIL-003`](#dd-mail-003-dkim-selector-verification) | Mail | `mail_dkim` | `WARN` | RFC 6376 |
| [`DD-MAIL-004`](#dd-mail-004-smtp-starttls-encryption) | Mail | `mail_starttls` | `WARN` | RFC 3207 |
| [`DD-MAIL-005`](#dd-mail-005-mta-sts-inbound-tls-policy) | Mail | `mail_mtasts` | `WARN` | RFC 8461 |
| [`DD-MAIL-006`](#dd-mail-006-bimi-brand-indicators) | Mail | `mail_bimi` | `INFO` | BIMI v1 |
| [`DD-SEC-001`](#dd-sec-001-dnssec-chain-of-trust) | Security | `dnssec` | `CRIT` | RFC 4033 / 4034 / 4035 |
| [`DD-SEC-002`](#dd-sec-002-dnssec-zone-walkability-nsec) | Security | `dnssec_nsec_walk` | `WARN` | RFC 4470 / RFC 5155 |
| [`DD-SEC-003`](#dd-sec-003-dane-tlsa-cryptographic-binding) | Security | `security_dane` | `CRIT` / `INFO` | RFC 6698 / RFC 7671 |
| [`DD-SEC-004`](#dd-sec-004-certificate-authority-authorization-caa) | Security | `security_caa` | `WARN` | RFC 8659 |
| [`DD-SEC-005`](#dd-sec-005-tls-certificate-hygiene--runway) | Security | `security_tls` | `CRIT` / `WARN` | NIST SP 800-52 |
| [`DD-SEC-006`](#dd-sec-006-subdomain-takeover-defense) | Security | `security_takeover` | `CRIT` | Cloud Signatures |
| [`DD-SEC-007`](#dd-sec-007-defensive-parked-domain-killswitch) | Security | `security_defensive` | `PASS` / `WARN` | RFC 7505 |
| [`DD-SEC-008`](#dd-sec-008-cdn-direct-to-origin-bypass) | Security | `security_cdn_origin` | `CRIT` | Perimeter Security |
| [`DD-SEC-009`](#dd-sec-009-psl-cookie-isolation-boundary) | Security | `psl_cookie_isolation` | `WARN` | RFC 6265bis / PSL |
| [`DD-SEC-010`](#dd-sec-010-http-cookie-scope--rfc-6265bis-hygiene) | Security | `security_cookie_scope` | `CRIT` / `WARN` | RFC 6265bis |
| [`DD-RES-001`](#dd-res-001-bgp-autonomous-system-diversity) | Resilience | `resilience_asn` | `WARN` | Team Cymru IP-to-ASN |
| [`DD-RES-002`](#dd-res-002-edns-client-subnet-geo-steering) | Resilience | `resilience_ecs` | `INFO` | RFC 7871 |
| [`DD-RES-003`](#dd-res-003-dns-flag-day-2020-buffer-compliance) | Resilience | `resilience_flagday` | `WARN` | DNS Flag Day 2020 |
| [`DD-RES-004`](#dd-res-004-dns-cookies-amplification-defense) | Resilience | `resilience_dns_cookies` | `INFO` | RFC 7873 / RFC 8749 |
| [`DD-REG-001`](#dd-reg-001-public-suffix-list-boundary) | Registration | `psl_boundary` | `CRIT` | publicsuffix.org |
| [`DD-REG-002`](#dd-reg-002-domain-registration-runway--transfer-lock) | Registration | `registration_rdap` | `CRIT` / `WARN` | RFC 9082 / RFC 9083 |
| [`DD-THR-001`](#dd-thr-001-certificate-transparency-shadow-discovery) | Threat | `threat_ct_logs` | `INFO` | RFC 6962 |
| [`DD-THR-002`](#dd-thr-002-homoglyph--bitsquatting-phishing-defense) | Threat | `threat_homograph` | `WARN` | Unicode TR39 |

---

## 1. DNS Core & Protocols (`DD-DNS`)

### `DD-DNS-001`: Authoritative Nameserver Redundancy
* **Executive Summary**: Verifies that the domain delegates to at least two synchronized, physically distinct authoritative nameservers.
* **Purpose**: Prevents single-point-of-failure outages where a single nameserver software failure, network hiccup, or host crash takes down all domain resolution.
* **What It Means**: RFC 1034 §4.1 and RFC 2182 mandate a minimum of two nameservers. This check queries parent delegations, tests IPv4/IPv6 glue reachability, and verifies that SOA serial numbers match across all nameservers.
* **Remediation**: Delegate the zone to at least two nameservers and configure AXFR/NOTIFY replication to synchronize SOA serials.

### `DD-DNS-002`: Authoritative Zone Transfer (AXFR)
* **Executive Summary**: Verifies that authoritative nameservers refuse unauthorized full zone transfer requests.
* **Purpose**: Prevents external attackers from downloading the entire zone file and exposing internal hostnames, staging endpoints, VPN gateways, and unlinked assets.
* **What It Means**: Initiates an RFC 5936 AXFR query to each authoritative nameserver. Compliant servers must return `Refused` or `NotAuth`.
* **Remediation**: Restrict zone transfers in BIND, NSD, or PowerDNS to authorized secondary IP addresses (`allow-transfer { none; };`).

### `DD-DNS-003`: Open DNS Recursion
* **Executive Summary**: Verifies that authoritative nameservers refuse recursive DNS lookups for third-party domains.
* **Purpose**: Prevents authoritative nameservers from being weaponized in high-volume DNS amplification and reflection DDoS attacks.
* **What It Means**: Sends a recursive query for an external domain (`example.com`) to each authoritative nameserver. Authoritative servers should respond with `Refused` or clear the Recursion Available (`ra`) flag.
* **Remediation**: Disable recursion globally on authoritative nameservers (`recursion no;`).

### `DD-DNS-004`: HTTPS / SVCB Service Binding
* **Executive Summary**: Audits DNS Type 65 (HTTPS) and Type 64 (SVCB) records for HTTP/3 ALPN and Encrypted Client Hello (ECH).
* **Purpose**: Enables modern browsers to initiate zero-RTT QUIC/HTTP/3 connections and encrypt the TLS Server Name Indication (SNI) to prevent network surveillance.
* **What It Means**: Queries Type 65 on apex and `www`. Parses `alpn`, `echconfig`, and port overrides.
* **Remediation**: Publish an HTTPS record: `<domain>. IN HTTPS 1 . alpn="h3,h2"`.

### `DD-DNS-005`: Wildcard DNS Scope
* **Executive Summary**: Detects catch-all wildcard DNS (`*.<domain>`) records and audits security risks.
* **Purpose**: Identifies wildcard records that can inadvertently route non-existent subdomains, break DMARC subdomain isolation, and disrupt dangling CNAME takeover auditing.
* **What It Means**: Sends queries for randomized 16-character pseudo-random subdomains. If they resolve to active IPs or CNAMEs, wildcard DNS is flagged.
* **Remediation**: Remove wildcard `*.` records if not required, or explicitly declare intended subdomains.

---

## 2. Negative Caching (`DD-NC`)

### `DD-NC-001`: RFC 2308 Negative Cache Staleness
* **Executive Summary**: Probes global Anycast resolvers to detect whether stale negative caches (NXDOMAIN/NODATA) are served while authoritative servers host live records.
* **Purpose**: Pinpoints DNS migration and record cutover outages where users see "domain not found" due to cached negative responses.
* **What It Means**: Queries Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), and OpenDNS. Computes effective negative cache TTL (`min(SOA.MINIMUM, SOA.TTL)`) and countdowns remaining seconds before eviction.
* **Remediation**: Lower the SOA MINIMUM field prior to migrations, or purge the resolver cache via provider web APIs.

---

## 3. Mail & Identity Security (`DD-MAIL`)

### `DD-MAIL-001`: SPF Mechanism Lookup Depth
* **Executive Summary**: Recursively counts DNS lookups in SPF records against the mandatory 10-lookup RFC 7208 ceiling.
* **Purpose**: Prevents email delivery failures (`PermError`) when receiving mail servers drop messages because SPF evaluation exceeded 10 DNS lookups.
* **What It Means**: Parses `v=spf1` records and traverses all `include:`, `a`, `mx`, `ptr`, and `exists:` mechanisms.
* **Remediation**: Flatten SPF records using IP blocks or remove obsolete sending services to stay strictly under 10 lookups.

### `DD-MAIL-002`: DMARC Policy Enforcement
* **Executive Summary**: Audits DMARC presence, enforcement mode (`p=reject`/`quarantine`), and reporting URIs (`rua`).
* **Purpose**: Stops attackers from sending phishing and spoofed emails that forge your domain name in the `From:` header.
* **What It Means**: Queries `_dmarc.<domain>`. Flags missing records, permissive `p=none` policies, and missing reporting inboxes.
* **Remediation**: Publish a DMARC policy with rejection enforcement: `v=DMARC1; p=reject; rua=mailto:dmarc@<domain>`.

### `DD-MAIL-003`: DKIM Selector Verification
* **Executive Summary**: Scans for active DomainKeys Identified Mail (DKIM) public keys across common sending provider selectors.
* **Purpose**: Confirms that cryptographic email signatures can be validated by recipient inboxes.
* **What It Means**: Probes 13 standard selectors (`google`, `k1`, `s1`, `selector1`, `mailgun`, `mandrill`, `default`, etc.) under `_domainkey.<domain>`.
* **Remediation**: Generate 2048-bit DKIM keys in your mail provider and publish the public key in DNS.

### `DD-MAIL-004`: SMTP STARTTLS Encryption
* **Executive Summary**: Connects to MX mail servers on TCP port 25 and verifies opportunistic TLS transport encryption.
* **Purpose**: Protects email in transit from passive wiretapping, surveillance, and cleartext sniffing.
* **What It Means**: Initiates SMTP handshake (`EHLO`), sends `STARTTLS`, and negotiates TLS cipher suites.
* **Remediation**: Enable TLS 1.3/1.2 on your mail transfer agent (MTA) with a valid CA certificate.

### `DD-MAIL-005`: MTA-STS Inbound TLS Policy
* **Executive Summary**: Audits Mail Transfer Agent Strict Transport Security (RFC 8461) and TLSRPT (RFC 8460).
* **Purpose**: Forces sending mail servers to deliver mail exclusively over authenticated TLS, preventing STARTTLS stripping attacks.
* **What It Means**: Queries `_mta-sts.<domain>` TXT, fetches HTTPS policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt`, and validates `_smtp._tls` TLSRPT reporting records.
* **Remediation**: Host an MTA-STS policy in `mode: enforce` and publish DNS TXT pointers.

### `DD-MAIL-006`: BIMI Brand Indicators
* **Executive Summary**: Audits Brand Indicators for Message Identification (BIMI) records and Verified Mark Certificates (VMC).
* **Purpose**: Displays authenticated brand logos in supporting email clients (Gmail, Apple Mail, Yahoo) and confirms prerequisite strict DMARC enforcement.
* **What It Means**: Queries `default._bimi.<domain>` for SVG logo (`l=`) and VMC certificate (`a=`) URLs, and verifies that DMARC is at `p=reject` or `p=quarantine; pct=100`.
* **Remediation**: Obtain a VMC certificate and host an SVG Tiny P-profile logo.

---

## 4. Cryptographic & Web Security (`DD-SEC`)

### `DD-SEC-001`: DNSSEC Chain-of-Trust
* **Executive Summary**: Validates end-to-end cryptographic DNSSEC authentication from the root zone down to child records.
* **Purpose**: Protects users from DNS spoofing, cache poisoning, and man-in-the-middle attacks that redirect traffic to fraudulent servers.
* **What It Means**: Verifies parent DS digests match the child Key Signing Key (KSK / DNSKEY 257) and that Zone Signing Keys (ZSK / DNSKEY 256) produce valid RRSIG signatures.
* **Remediation**: Sign the zone with modern algorithms (e.g. ECDSAP256SHA256) and submit the DS record to your registrar.

### `DD-SEC-002`: DNSSEC Zone Walkability (NSEC)
* **Executive Summary**: Tests NXDOMAIN denial-of-existence responses to detect zone enumeration vulnerabilities.
* **Purpose**: Prevents attackers from mapping all subdomains, private hosts, and infrastructure by walking plaintext NSEC chains.
* **What It Means**: Sends a query for a non-existent name with DNSSEC DO bit set. Checks if the response returns cleartext `NSEC` (RFC 4034) or hashed `NSEC3` (RFC 5155).
* **Remediation**: Configure authoritative nameservers to use salted NSEC3 or dynamic "white lies" minimal NSEC.

### `DD-SEC-003`: DANE TLSA Cryptographic Binding
* **Executive Summary**: Audits DANE TLSA records on port 25 (SMTP) and port 443 (HTTPS).
* **Purpose**: Pins service certificates directly to the DNSSEC root of trust, preventing compromised WebPKI Certificate Authorities from issuing rogue certificates.
* **What It Means**: Queries `_443._tcp.<domain>` and `_25._tcp.<mx>` for TLSA records (RFC 6698 / 7671). Validates that DNSSEC is active.
* **Remediation**: Publish TLSA records under a DNSSEC-signed zone for your mail and web services.

### `DD-SEC-004`: Certificate Authority Authorization (CAA)
* **Executive Summary**: Audits CAA records designating authorized public Certificate Authorities.
* **Purpose**: Prevents unauthorized or fraudulent SSL/TLS certificates from being issued by untrusted CAs.
* **What It Means**: Queries `CAA` records for `issue`, `issuewild`, and `iodef` (incident reporting) tags.
* **Remediation**: Publish CAA records explicitly naming your CAs: `<domain>. IN CAA 0 issue "letsencrypt.org"`.

### `DD-SEC-005`: TLS Certificate Hygiene & Runway
* **Executive Summary**: Probes web servers on port 443 to evaluate certificate validity, expiration runway, and SAN coverage.
* **Purpose**: Prevents service downtime caused by unexpected certificate expiration and flags missing Subject Alternative Names.
* **What It Means**: Initiates a TLS handshake to `<domain>:443`. Alerts if the certificate expires within 30 days or if the requested hostname is not in the SAN list.
* **Remediation**: Automate certificate renewals via ACME/Let's Encrypt and verify SAN coverage.

### `DD-SEC-006`: Subdomain Takeover Defense
* **Executive Summary**: Cross-references unresolvable CNAME targets against known cloud provider abandonment signatures.
* **Purpose**: Prevents attackers from claiming abandoned subdomains on AWS S3, GitHub Pages, Heroku, Azure, or CloudFront and serving malicious content.
* **What It Means**: Resolves CNAME records. If the target returns NXDOMAIN and matches cloud provider domain patterns, it flags high-risk dangling pointers.
* **Remediation**: Delete dangling CNAME records or claim the resource in your cloud dashboard.

### `DD-SEC-007`: Defensive Parked Domain Killswitch
* **Executive Summary**: Evaluates non-sending and parked domains for RFC 7505 Null MX and anti-spoofing policies.
* **Purpose**: Prevents attackers from using inactive or defensive domain registrations to send spoofed spam and phishing.
* **What It Means**: Verifies whether parked domains publish Null MX (`MX 0 .`), hard-fail SPF (`v=spf1 -all`), and reject DMARC (`p=reject; sp=reject`).
* **Remediation**: Publish `MX 0 .` and `v=spf1 -all` on all domains that do not send or receive email.

### `DD-SEC-008`: CDN Direct-to-Origin Bypass
* **Executive Summary**: Detects exposed origin backend IPs bypassing reverse-proxy CDN/WAF defenses.
* **Purpose**: Prevents attackers from circumventing Cloudflare/Fastly DDoS mitigation and WAF security rules by attacking the origin IP directly.
* **What It Means**: Checks if the apex is on a CDN IP range, then inspects MX records, SPF IPs, and subdomains (`origin.`, `direct.`, `cpanel.`) for leaked origin addresses.
* **Remediation**: Delete unproxied origin DNS records and restrict origin firewall ports to CDN IP blocks.

### `DD-SEC-009`: PSL Cookie Isolation Boundary
* **Executive Summary**: Audits wildcard DNS and multi-tenant subdomains against cross-tenant cookie tossing and session fixation.
* **Purpose**: Prevents malicious users on one subdomain (`tenant1.<domain>`) from writing cookies for `.domain` that compromise other tenants.
* **What It Means**: Verifies whether domains hosting wildcard subdomains are registered in the Public Suffix List Private Section to enforce browser cookie isolation.
* **Remediation**: Isolate user-generated content on a dedicated sandbox domain (e.g., `googleusercontent.com`) or submit your suffix to the PSL.

### `DD-SEC-010`: HTTP Cookie Scope & RFC 6265bis Hygiene
* **Executive Summary**: Audits HTTP `Set-Cookie` headers for Supercookie PSL violations, over-scoped domains, and prefix restrictions.
* **Purpose**: Prevents browsers from rejecting stateful cookies and stops sensitive session tokens from leaking to untrusted subdomains.
* **What It Means**: Fetches web landing pages and parses `Set-Cookie` attributes. Flags cookies matching Public Suffixes (Supercookies), `__Host-` cookies with `Domain` attributes, missing `Secure` flags, and missing `SameSite`.
* **Remediation**: Omit the `Domain` attribute to enforce Host-Only cookies and adopt `__Host-` prefixes for session tokens.

---

## 5. Resilience & Routing (`DD-RES`)

### `DD-RES-001`: BGP Autonomous System Diversity
* **Executive Summary**: Maps authoritative nameserver IPs to BGP Autonomous Systems (ASNs) via Team Cymru DNS.
* **Purpose**: Prevents total DNS failure caused by single-carrier routing outages, BGP hijacks, or transit link failures.
* **What It Means**: Resolves each nameserver IP against `origin.asn.cymru.com`. Alerts if all nameservers originate from a single BGP ASN.
* **Remediation**: Deploy secondary nameservers across a secondary cloud or DNS provider on a disjoint ASN.

### `DD-RES-002`: EDNS Client Subnet (ECS) Geo-Steering
* **Executive Summary**: Probes nameservers with simulated client IP subnets from North America, Europe, and Asia-Pacific.
* **Purpose**: Audits Anycast routing health and split-horizon geo-DNS steering consistency.
* **What It Means**: Sends queries with `EDNS0_SUBNET` options (RFC 7871) for US, EU, and APAC IP blocks and compares returned A/AAAA answer sets.
* **Remediation**: Verify geo-DNS routing rules in your authoritative DNS console.

### `DD-RES-003`: DNS Flag Day 2020 Buffer Compliance
* **Executive Summary**: Tests authoritative nameserver EDNS0 buffer limits (recommended max 1232 bytes).
* **Purpose**: Eliminates UDP IP packet fragmentation attacks (Poison Over Fragment) that poison resolver caches.
* **What It Means**: Queries nameservers with EDNS0 buffer size 1232. Flags nameservers advertising buffer sizes exceeding 1472 bytes over UDP.
* **Remediation**: Configure authoritative DNS daemons (e.g. BIND `max-udp-size 1232`) to limit UDP buffer sizing.

### `DD-RES-004`: DNS Cookies Amplification Defense
* **Executive Summary**: Probes authoritative nameservers for EDNS0 Server Cookie support (RFC 7873 / RFC 8749).
* **Purpose**: Mitigates DNS reflection and amplification DDoS attacks and protects clients against request spoofing.
* **What It Means**: Sends queries with an 8-byte client cookie in an EDNS0 OPT RR and verifies whether a valid Server Cookie is returned.
* **Remediation**: Enable DNS Cookies in your authoritative nameserver configuration.

---

## 6. Registration & Lifecycle (`DD-REG`)

### `DD-REG-001`: Public Suffix List Boundary
* **Executive Summary**: Validates organizational domain boundaries (`eTLD+1`) and warns against scanning public suffixes directly.
* **Purpose**: Ensures diagnostic rules anchor to registrable domain boundaries and clarifies private platform tenant hosting.
* **What It Means**: Queries Mozilla's Public Suffix List via `golang.org/x/net/publicsuffix`. Flags when a public suffix itself (e.g. `co.uk`, `github.io`) is audited.
* **Remediation**: Scan individual registrable domains rather than the public suffix itself.

### `DD-REG-002`: Domain Registration Runway & Transfer Lock
* **Executive Summary**: Audits domain expiration runways and registrar transfer locking via ICANN RDAP.
* **Purpose**: Prevents accidental domain expiration and stops social engineering domain hijacking attempts.
* **What It Means**: Queries registry RDAP endpoints (RFC 9082 / 9083). Alerts if expiration is within 30 days or if `clientTransferProhibited` is missing.
* **Remediation**: Renew domain registration early and enable Registrar Transfer Lock.

---

## 7. Threat Intelligence (`DD-THR`)

### `DD-THR-001`: Certificate Transparency Shadow Discovery
* **Executive Summary**: Discovers unmanaged or shadow subdomains published in public Certificate Transparency logs.
* **Purpose**: Uncovers forgotten development, staging, or administrative endpoints that widen your attack surface.
* **What It Means**: Queries `crt.sh` JSON APIs for historical certificates issued under the apex domain.
* **Remediation**: Audit discovered subdomains and decommission obsolete DNS records or endpoints.

### `DD-THR-002`: Homoglyph & Bitsquatting Phishing Defense
* **Executive Summary**: Probes Unicode IDNA confusables and single-bit memory error permutations for active lookalikes.
* **Purpose**: Identifies brand impersonation, typosquatting, and phishing sites targeting your customers or employees.
* **What It Means**: Generates Cyrillic/Greek homoglyphs (Unicode TR39) and bit-flip variations. Checks if any are actively registered in DNS.
* **Remediation**: Defensively register lookalike domains or monitor them via brand protection services.
