package main

import (
	"fmt"
	"strings"
	"time"
)

var (
	version = "0.1.0"
	commit  = "none"
	date    = "unknown"
)

func formatVersion() string {
	cleanVersion := strings.TrimPrefix(version, "v")
	year := time.Now().Year()
	return fmt.Sprintf("domain-doctor %s (commit: %s, date: %s)\nCopyright (c) %d smford\nLicensed under the MIT licence.",
		cleanVersion, commit, date, year)
}
