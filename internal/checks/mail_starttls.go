package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
	"github.com/smford/domain-doctor/internal/prober"
)

type MailSTARTTLSCheck struct{}

func (c *MailSTARTTLSCheck) ID() string       { return "DD-MAIL-004" }
func (c *MailSTARTTLSCheck) Name() string     { return "mail_starttls" }
func (c *MailSTARTTLSCheck) Category() string { return "Mail" }

func (c *MailSTARTTLSCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", execCtx.Domain, dns.TypeMX)
	if err != nil || msg == nil || len(msg.Answer) == 0 {
		execCtx.AddFinding(engine.Finding{
			ID:       "MAIL-NO-MX",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  "No MX records configured for domain",
			Detail:   "Domain cannot receive incoming mail directly via dedicated MX exchange.",
		})
		return nil
	}

	mxHosts := make([]string, 0)
	for _, ans := range msg.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			host := strings.TrimSuffix(mx.Mx, ".")
			mxHosts = append(mxHosts, host)
			execCtx.AddRecord("MX", fmt.Sprintf("%d %s", mx.Preference, host))

			// RFC 2181 check: MX target must not point to a CNAME
			cnameMsg, _, _ := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", host, dns.TypeCNAME)
			if cnameMsg != nil && len(cnameMsg.Answer) > 0 {
				execCtx.AddFinding(engine.Finding{
					ID:       "MAIL-MX-CNAME-VIOLATION",
					Category: c.Category(),
					Severity: engine.SeverityWarning,
					Summary:  fmt.Sprintf("MX record points to a CNAME alias (%s)", host),
					Detail:   "RFC 2181 §10.3 explicitly prohibits MX records from pointing to CNAME aliases. Some MTAs may fail mail delivery.",
				})
			}
		}
	}

	if len(mxHosts) == 0 {
		return nil
	}

	primaryMX := mxHosts[0]

	// Probe port 25 STARTTLS
	starttlsCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	res, probeErr := prober.ProbeSTARTTLS(starttlsCtx, primaryMX, 25, 3*time.Second)
	if probeErr != nil {
		// Port 25 is frequently blocked on residential and cloud egress (AWS, GCP, residential ISPs)
		execCtx.AddFinding(engine.Finding{
			ID:       "MAIL-STARTTLS-PROBE-BLOCKED",
			Category: c.Category(),
			Severity: engine.SeverityInfo,
			Summary:  fmt.Sprintf("Port 25 STARTTLS probe could not connect to %s", primaryMX),
			Detail:   fmt.Sprintf("Connection note: %v. This is common when testing from networks with outbound port 25 egress restrictions.", probeErr),
		})
		return nil
	}

	versionName := "Unknown"
	switch res.Version {
	case tls.VersionTLS13:
		versionName = "TLS 1.3"
	case tls.VersionTLS12:
		versionName = "TLS 1.2"
	case tls.VersionTLS11:
		versionName = "TLS 1.1"
	case tls.VersionTLS10:
		versionName = "TLS 1.0"
	}

	if res.Version < tls.VersionTLS12 {
		execCtx.AddFinding(engine.Finding{
			ID:       "MAIL-STARTTLS-WEAK-VERSION",
			Category: c.Category(),
			Severity: engine.SeverityWarning,
			Summary:  fmt.Sprintf("MX host %s negotiated legacy %s", primaryMX, versionName),
			Detail:   "Mail servers should enforce TLS 1.2 or TLS 1.3 to ensure transport encryption security.",
		})
	} else {
		execCtx.AddFinding(engine.Finding{
			ID:       "MAIL-STARTTLS-SECURE",
			Category: c.Category(),
			Severity: engine.SeverityPass,
			Summary:  fmt.Sprintf("In-transit opportunistic encryption active on %s (%s)", primaryMX, versionName),
			Detail:   fmt.Sprintf("Cipher Suite: 0x%04x. Outgoing email transfer to this host is encrypted against eavesdropping.", res.CipherSuite),
		})
	}

	return nil
}
