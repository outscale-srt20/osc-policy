package main

import (
	"fmt"
	"os"

	"github.com/outscale-srt20/osc-policy/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
