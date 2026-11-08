package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// runReport is `hasr report`: scan JSON + mapping CSV (+ policy) -> HTML and JSON.
// Exit codes: 0 ok, 2 usage, input or output error.
func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	scanPath := fs.String("scan", "", "scan JSON written by `hasr scan` (required)")
	mapPath := fs.String("map", "", "mapping CSV (required)")
	policyPath := fs.String("policy", defaultPolicyFile, "policy JSON: classification levels and the X, Y, Z values with their sources")
	htmlPath := fs.String("html", "hasr-report.html", "HTML report to write")
	jsonPath := fs.String("json", "hasr-report.json", "JSON report to write")
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *scanPath == "" || *mapPath == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}

	scan, err := readScan(*scanPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading scan:", err)
		return 2
	}
	now := time.Now().UTC().Truncate(time.Second)
	pol, err := loadPolicy(*policyPath, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading policy:", err)
		return 2
	}
	mapping, err := readMapping(*mapPath, pol.labels())
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading mapping:", err)
		return 2
	}

	inputs := Inputs{
		ScanFile:          *scanPath,
		ScanGeneratedAt:   scan.GeneratedAt,
		ScanSchemaVersion: scan.SchemaVersion,
		ScanTool:          scan.Tool,
		MappingFile:       *mapPath,
		PolicyFile:        *policyPath,
	}
	r := buildReport(scan, inputs, mapping, pol, now)
	r.Tool = Tool{Name: "hasr", Go: runtime.Version()}

	var page bytes.Buffer
	if err := writeHTML(&page, r); err != nil {
		fmt.Fprintln(os.Stderr, "rendering HTML:", err)
		return 2
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "encoding JSON:", err)
		return 2
	}
	if err := os.WriteFile(*htmlPath, page.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := os.WriteFile(*jsonPath, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	c := r.Completeness
	fmt.Fprintf(os.Stderr, "wrote %s and %s: %d of %d mapped targets assessed; %d need owner input; %d mapped but not scanned; %d not assessed\n",
		*htmlPath, *jsonPath, c.Assessed, c.Mapped, c.NeedsOwnerInput, c.MappedNotScanned, c.NotAssessed)
	if len(r.MissingValues) > 0 {
		fmt.Fprintf(os.Stderr, "values not set yet: %s\n", strings.Join(r.MissingValues, "; "))
	}
	return 0
}

func readScan(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	var r Report
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return Report{}, fmt.Errorf("%s: %w", path, err)
	}
	if r.SchemaVersion != schemaVersion {
		return Report{}, fmt.Errorf("%s: scan schema %q, this hasr reads %q; re-run hasr scan", path, r.SchemaVersion, schemaVersion)
	}
	return r, nil
}
