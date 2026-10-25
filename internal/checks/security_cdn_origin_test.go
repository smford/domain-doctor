package checks

import (
	"testing"
)

func TestIsCDNIP(t *testing.T) {
	// Cloudflare IP
	if !isCDNIP("104.16.123.96") {
		t.Errorf("expected 104.16.123.96 to be identified as CDN IP")
	}

	// Fastly IP
	if !isCDNIP("151.101.1.69") {
		t.Errorf("expected 151.101.1.69 to be identified as CDN IP")
	}

	// Standard Non-CDN public IP
	if isCDNIP("8.8.8.8") {
		t.Errorf("expected 8.8.8.8 to NOT be identified as CDN IP")
	}

	// Invalid IP string
	if isCDNIP("not-an-ip") {
		t.Errorf("expected invalid IP string to return false")
	}
}
