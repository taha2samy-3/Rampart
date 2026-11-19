package main

import (
	"fmt"
	"os"
)

func main() {
	if err := ParseSPDXStream(os.Stdin, os.Stdout, Options{}); err != nil {
		fmt.Fprintf(os.Stderr, "spdx sbom parser error: %v\n", err)
		os.Exit(1)
	}
}
