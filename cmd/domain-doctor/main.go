package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func formatVersion() string {
	cleanVersion := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("domain-doctor %s (commit: %s, date: %s)\nCopyright (c) %d smford\nLicensed under the MIT licence.",
		cleanVersion, commit, date, time.Now().Year())
}

func main() {
	var showVersion bool
	var servePort string

	flag.BoolVar(&showVersion, "version", false, "display version information")
	flag.BoolVar(&showVersion, "v", false, "display version information (shorthand)")
	flag.StringVar(&servePort, "port", "8080", "port to serve health endpoint")
	flag.StringVar(&servePort, "p", "8080", "port to serve health endpoint (shorthand)")

	flag.Parse()

	if showVersion {
		fmt.Println(formatVersion())
		os.Exit(0)
	}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","app":"domain-doctor"}`))
	})

	addr := ":" + servePort
	fmt.Printf("domain-doctor server listening on %s...\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Error running server: %v\n", err)
		os.Exit(1)
	}
}
