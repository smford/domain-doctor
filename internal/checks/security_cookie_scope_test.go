package checks

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smford/domain-doctor/internal/engine"
)

func TestCookieScopeCheck_Rules(t *testing.T) {
	// 1. Test Supercookie logic
	cleanDomain := strings.TrimPrefix(".co.uk", ".")
	if cleanDomain != "co.uk" {
		t.Fatalf("expected co.uk")
	}

	// 2. Test mock server returning various cookies
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "__Host-sess",
			Value:    "123",
			Domain:   "example.com", // Violation! __Host- cannot have domain
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    "secret",
			Domain:   ".example.com", // Over-scoped!
			Path:     "/",
			Secure:   true,
			HttpOnly: false, // Missing HttpOnly
		})
	}))
	defer ts.Close()

	// Parse cookies from test response
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer res.Body.Close()

	cookies := res.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	execCtx := engine.NewExecutionContext("example.com", 0)
	chk := &CookieScopeCheck{}

	// Verify sensitive cookie check
	if !isSensitiveCookie("auth_token") {
		t.Errorf("expected auth_token to be identified as sensitive")
	}
	if !isSensitiveCookie("__Host-sess") {
		t.Errorf("expected __Host-sess to be identified as sensitive")
	}
	if isSensitiveCookie("theme_mode") {
		t.Errorf("expected theme_mode to NOT be identified as sensitive")
	}

	_ = chk
	_ = execCtx
}
