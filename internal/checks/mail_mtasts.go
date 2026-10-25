package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type MTASTSCheck struct{}

func (c *MTASTSCheck) Name() string     { return "mail_mtasts" }
func (c *MTASTSCheck) Category() string { return "Mail" }

func (c *MTASTSCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	// 1. Check MTA-STS DNS record: _mta-sts.<domain>
	mtaStsHost := fmt.Sprintf("_mta-sts.%s", execCtx.Domain)
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", mtaStsHost, dns.TypeTXT)

	var mtaStsRecord string
	if err == nil && msg != nil {
		for _, ans := range msg.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				full := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.TrimSpace(full), "v=STSv1") {
					mtaStsRecord = full
					execCtx.AddRecord("MTA-STS", full)
					break
				}
			}
		}
	}

	if mtaStsRecord == "" {
		execCtx.AddFinding(engine.Finding{
			ID:       "MTA-STS-MISSING",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  fmt.Sprintf("MTA-STS policy record missing at %s", mtaStsHost),
			Detail:   "Without MTA-STS (RFC 8461), opportunistic STARTTLS on inbound SMTP can be stripped by man-in-the-middle attackers without detection.",
			Remediation: &engine.Remediation{
				Title:       "Publish MTA-STS Record and Policy",
				RecordType:  "TXT",
				Suggested:   fmt.Sprintf("_mta-sts.%s. IN TXT \"v=STSv1; id=%d;\"", execCtx.Domain, time.Now().Unix()),
				Explanation: "Deploy a valid HTTPS policy at https://mta-sts." + execCtx.Domain + "/.well-known/mta-sts.txt and advertise it in DNS.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc8461",
			},
		})
	} else {
		// Attempt to fetch HTTPS policy file
		policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", execCtx.Domain)
		client := &http.Client{
			Timeout: 4 * time.Second,
		}
		req, reqErr := http.NewRequestWithContext(ctx, "GET", policyURL, nil)
		if reqErr == nil {
			req.Header.Set("User-Agent", "domain-doctor/0.1.0 (authoritative-audit)")
			resp, httpErr := client.Do(req)
			if httpErr != nil || resp.StatusCode != http.StatusOK {
				statusStr := "unreachable"
				if resp != nil {
					statusStr = fmt.Sprintf("HTTP %d", resp.StatusCode)
				}
				execCtx.AddFinding(engine.Finding{
					ID:       "MTA-STS-POLICY-FETCH-FAILED",
					Category: c.Category(),
					Severity: engine.SeverityWarning,
					Summary:  fmt.Sprintf("MTA-STS DNS advertised but policy file is %s (%s)", statusStr, policyURL),
					Detail:   "Sending MTAs will fail to validate the policy or fall back to insecure transport if the policy endpoint is not serving HTTP 200 over valid TLS.",
				})
			} else {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				mode, mxList, maxAge := parseMTASTSPolicy(string(body))
				if mode == "enforce" {
					execCtx.AddFinding(engine.Finding{
						ID:       "MTA-STS-ENFORCED",
						Category: c.Category(),
						Severity: engine.SeverityPass,
						Summary:  fmt.Sprintf("MTA-STS policy enforced (mode: enforce, max_age: %s, MX: [%s])", maxAge, strings.Join(mxList, ", ")),
						Detail:   "Inbound email transport strictly mandates TLS encryption with valid CA certificate verification.",
					})
				} else if mode == "testing" {
					execCtx.AddFinding(engine.Finding{
						ID:       "MTA-STS-TESTING",
						Category: c.Category(),
						Severity: engine.SeverityWarning,
						Summary:  fmt.Sprintf("MTA-STS is active in report-only 'testing' mode (max_age: %s)", maxAge),
						Detail:   "Sending MTAs will report failures via TLSRPT but will not reject unencrypted or misconfigured mail connections until switched to 'enforce'.",
					})
				} else {
					execCtx.AddFinding(engine.Finding{
						ID:       "MTA-STS-POLICY-ACTIVE",
						Category: c.Category(),
						Severity: engine.SeverityInfo,
						Summary:  fmt.Sprintf("MTA-STS policy reachable with mode: %s", mode),
						Detail:   fmt.Sprintf("Policy parsed from %s", policyURL),
					})
				}
			}
		}
	}

	// 2. Check SMTP TLSRPT: _smtp._tls.<domain>
	tlsrptHost := fmt.Sprintf("_smtp._tls.%s", execCtx.Domain)
	rptMsg, _, rptErr := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", tlsrptHost, dns.TypeTXT)

	var tlsrptRecord string
	if rptErr == nil && rptMsg != nil {
		for _, ans := range rptMsg.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				full := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.TrimSpace(full), "v=TLSRPTv1") {
					tlsrptRecord = full
					execCtx.AddRecord("TLSRPT", full)
					break
				}
			}
		}
	}

	if tlsrptRecord != "" {
		execCtx.AddFinding(engine.Finding{
			ID:       "TLSRPT-CONFIGURED",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("SMTP TLS Reporting (TLSRPT RFC 8460) enabled: %s", tlsrptRecord),
			Detail:   "Receives automated daily JSON telemetry reports on inbound STARTTLS and MTA-STS delivery failures.",
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "TLSRPT-MISSING",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  fmt.Sprintf("SMTP TLS Reporting (TLSRPT) record missing at %s", tlsrptHost),
			Detail:   "Without TLSRPT (RFC 8460), sending mail servers cannot report TLS delivery failures, certificate expiration, or handshake aborts.",
			Remediation: &engine.Remediation{
				Title:       "Publish TLSRPT Record",
				RecordType:  "TXT",
				Suggested:   fmt.Sprintf("_smtp._tls.%s. IN TXT \"v=TLSRPTv1; rua=mailto:tlsrpt@%s\"", execCtx.Domain, execCtx.Domain),
				Explanation: "Designate a reporting inbox to receive aggregated telemetry reports from Google, Microsoft, and other compliant mail servers.",
				DocURL:      "https://datatracker.ietf.org/doc/html/rfc8460",
			},
		})
	}

	return nil
}

func parseMTASTSPolicy(body string) (mode string, mxList []string, maxAge string) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "mode:") {
			mode = strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
		} else if strings.HasPrefix(line, "mx:") {
			mx := strings.TrimSpace(strings.TrimPrefix(line, "mx:"))
			if mx != "" {
				mxList = append(mxList, mx)
			}
		} else if strings.HasPrefix(line, "max_age:") {
			maxAge = strings.TrimSpace(strings.TrimPrefix(line, "max_age:"))
		}
	}
	return mode, mxList, maxAge
}
