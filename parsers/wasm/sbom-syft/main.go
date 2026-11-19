package main

import (
	"fmt"
	"io"
	"os"
)

// errWriter is where the reader says what it skipped; the host keeps the end of it for the run.
var errWriter io.Writer = os.Stderr

func main() {
	if err := ParseSyftStream(os.Stdin, os.Stdout, Options{}); err != nil {
		fmt.Fprintf(os.Stderr, "syft sbom parser error: %v\n", err)
		os.Exit(1)
	}
}
