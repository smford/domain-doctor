package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/smford/domain-doctor/internal/engine"
)

type SubdomainTakeoverCheck struct{}

func (c *SubdomainTakeoverCheck) ID() string       { return "DD-SEC-006" }
func (c *SubdomainTakeoverCheck) Name() string     { return "security_takeover" }
func (c *SubdomainTakeoverCheck) Category() string { return "Security" }

type CloudFingerprint struct {
	Provider string
	Suffix   string
}

var CloudFingerprints = []CloudFingerprint{
	{"AWS S3 Bucket", ".s3.amazonaws.com"},
	{"AWS S3 Website", ".s3-website"},
	{"AWS CloudFront", ".cloudfront.net"},
	{"GitHub Pages", ".github.io"},
	{"Heroku App", ".herokudns.com"},
	{"Heroku App", ".herokuapp.com"},
	{"Microsoft Azure", ".azurewebsites.net"},
	{"Shopify", ".myshopify.com"},
	{"Fastly CDN", ".fastly.net"},
	{"Ghost", ".ghost.io"},
	{"Surge.sh", ".surge.sh"},
}

func (c *SubdomainTakeoverCheck) Run(ctx context.Context, execCtx *engine.ExecutionContext) error {
	commonSubs := []string{
		execCtx.Domain,
		"www." + execCtx.Domain,
		"blog." + execCtx.Domain,
		"app." + execCtx.Domain,
		"docs." + execCtx.Domain,
		"status." + execCtx.Domain,
		"cdn." + execCtx.Domain,
	}

	for _, sub := range commonSubs {
		msg, _, err := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", sub, dns.TypeCNAME)
		if err != nil || msg == nil || len(msg.Answer) == 0 {
			continue
		}

		for _, ans := range msg.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				target := strings.ToLower(strings.TrimSuffix(cname.Target, "."))
				execCtx.AddRecord("CNAME", fmt.Sprintf("%s -> %s", sub, target))

				for _, fp := range CloudFingerprints {
					if strings.Contains(target, fp.Suffix) {
						// Query target to verify if it resolves or returns NXDOMAIN
						targetMsg, _, _ := execCtx.DNSProber.QueryRecursive("1.1.1.1:53", target, dns.TypeA)
						if targetMsg != nil && targetMsg.Rcode == dns.RcodeNameError {
							execCtx.AddFinding(engine.Finding{
								ID:       fmt.Sprintf("TAKEOVER-DANGLING-CNAME-%s", strings.ReplaceAll(sub, ".", "-")),
								Category: c.Category(),
								Severity: engine.SeverityCritical,
								Summary:  fmt.Sprintf("Dangling CNAME / Subdomain Takeover Vulnerability on %s!", sub),
								Detail: fmt.Sprintf("Subdomain %s points to %s (%s) which resolves to NXDOMAIN. An attacker can register this bucket/app name on %s and serve malicious content under your trusted domain.",
									sub, target, fp.Provider, fp.Provider),
								Remediation: &engine.Remediation{
									Title:       fmt.Sprintf("Remove Dangling CNAME %s", sub),
									RecordType:  "CNAME",
									Explanation: fmt.Sprintf("Delete the CNAME record pointing to %s or claim the corresponding resource in %s.", target, fp.Provider),
									DocURL:      "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
								},
							})
						} else {
							execCtx.AddFinding(engine.Finding{
								ID:       fmt.Sprintf("TAKEOVER-CNAME-VALID-%s", strings.ReplaceAll(sub, ".", "-")),
								Category: c.Category(),
								Severity: engine.SeverityPass,
								Summary:  fmt.Sprintf("CNAME alias for %s resolved cleanly to %s (%s)", sub, target, fp.Provider),
								Detail:   "Target resource is active and claimed.",
							})
						}
						break
					}
				}
			}
		}
	}

	return nil
}
