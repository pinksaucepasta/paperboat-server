package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat-server/internal/testdoctor"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	jsonOutput := false
	if len(args) == 2 && args[0] == "doctor" && args[1] == "--json" {
		jsonOutput = true
	} else if len(args) != 1 || args[0] != "doctor" {
		fmt.Fprintln(os.Stderr, "usage: paperboat-test doctor [--json]")
		return 2
	}
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "paperboat-test: cannot determine working directory")
		return 1
	}
	if filepath.Base(root) != "paperboat-server" {
		fmt.Fprintln(os.Stderr, "paperboat-test: run from the paperboat-server repository")
		return 1
	}
	report := (testdoctor.Runner{Root: root}).Run(context.Background())
	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			return 1
		}
	} else {
		for _, check := range report.Checks {
			fmt.Fprintf(os.Stdout, "%-4s %-24s %s\n", check.Status, check.Code, check.Summary)
			if check.Recovery != "" {
				fmt.Fprintf(os.Stdout, "     recovery: %s\n", check.Recovery)
			}
		}
		fmt.Fprintf(os.Stdout, "status: %s\n", report.Status)
	}
	if report.Status == testdoctor.Fail {
		return 1
	}
	return 0
}
