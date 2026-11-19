package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	opts := Options{ExtractVulnerabilities: envTrue("EXTRACT_VULNERABILITIES")}
	if err := ParseCycloneDXStream(os.Stdin, os.Stdout, opts); err != nil {
		fmt.Fprintf(os.Stderr, "cyclonedx sbom parser error: %v\n", err)
		os.Exit(1)
	}
}

// envTrue reads a switch the host sets in the environment.
func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
