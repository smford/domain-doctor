package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFormatVersion(t *testing.T) {
	version = "v0.1.0"
	commit = "061249499a9e04abd339865591c4148f31b1a5ea"
	date = "2026-10-25T19:00:00Z"

	out := formatVersion()
	lines := strings.Split(out, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines in version output, got %d:\n%s", len(lines), out)
	}

	if !strings.HasPrefix(lines[0], "domain-doctor 0.1.0 (commit: 061249499a9e04abd339865591c4148f31b1a5ea, date: 2026-10-25T19:00:00Z)") {
		t.Errorf("line 1 unexpected: %s", lines[0])
	}
	if !strings.Contains(lines[1], "Copyright (c)") || !strings.Contains(lines[1], "smford") {
		t.Errorf("line 2 unexpected: %s", lines[1])
	}
	if lines[2] != "Licensed under the MIT licence." {
		t.Errorf("line 3 unexpected: %s", lines[2])
	}
}

func TestHealthzEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","app":"domain-doctor"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}
