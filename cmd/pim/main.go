// Command pim is the entrypoint for PiM, a self-hosted vulnerability
// assessment platform. For now it only reports its version; the agents and the
// localhost API are added in later tasks.
package main

import (
	"fmt"
	"os"

	"github.com/Miguel7293/PiM-/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pim:", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Printf("PiM %s — Potential-vulnerability Intelligence Mapper\n", version.Version)
	return nil
}
