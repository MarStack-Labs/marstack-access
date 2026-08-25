package main

import (
	"fmt"
	"os"

	"github.com/marstack-labs/marstack-access/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
