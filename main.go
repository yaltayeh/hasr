// Command hasr inventories the cryptography of TLS endpoints and reports it
// against SAMA Circular No. 482021280.
//
// `hasr scan` runs, for each host:port, a fixed set of ordinary TLS
// handshakes, each with a different offer (see probeSpecs), records what the
// server accepted, classifies the endpoint and writes JSON. It sends no
// application data and does no intrusive testing. Only run it against targets
// you own or are authorised to assess.
//
// `hasr report` joins a scan with the mapping CSV (owners, data classification,
// Mosca values) and writes an HTML report and its JSON.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// schemaVersion 0.4 added canonical_name; readScan also accepts 0.3.
const schemaVersion = "0.4"

// Report is the JSON document. PROVISIONAL: the schema is not frozen.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          Tool      `json:"tool"`
	GeneratedAt   time.Time `json:"generated_at"`
	Targets       []Target  `json:"targets"`
}

type Tool struct {
	Name string `json:"name"`
	Go   string `json:"go"`
}

type Target struct {
	Target    string    `json:"target"`
	ScannedAt time.Time `json:"scanned_at"`
	Error     string    `json:"error,omitempty"` // the target itself was invalid
	// CanonicalName is the end of the host's CNAME chain, when it differs from
	// the host. The report matches cloud endpoints against it.
	CanonicalName string        `json:"canonical_name,omitempty"`
	Probes        []Probe       `json:"probes"`
	Certificates  []Certificate `json:"certificates"`
	Summary       Summary       `json:"summary"`

	// managedTLS is set by the report when a matched cloud record shows the
	// TLS policy is a managed setting. Not part of the scan JSON.
	managedTLS bool
}

const usage = `usage:
  hasr scan [-table] [-timeout 5s] [--targets mapping.csv] [host:port ...]
  hasr cloud aws --from RAW_DIR > aws.json
  hasr report --scan scan.json --map mapping.csv [--cloud aws.json ...] [--policy policy.json] [--html hasr-report.html] [--json hasr-report.json]

Flags go before the targets. Only scan targets you own or are authorised to assess.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "report":
		os.Exit(runReport(os.Args[2:]))
	case "cloud":
		os.Exit(runCloud(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

// runScan is `hasr scan`. Exit codes: 0 ok, 1 some target had no accepted
// probe (or was invalid), 2 usage, input or output error.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	table := fs.Bool("table", false, "print a human-readable table instead of JSON")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout per handshake attempt")
	targetsFile := fs.String("targets", "", "mapping CSV whose target column lists hosts to scan")
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var targets []string
	seen := map[string]bool{}
	addTarget := func(t string) {
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	if *targetsFile != "" {
		entries, err := readMapping(*targetsFile, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "reading targets:", err)
			return 2
		}
		for _, e := range entries {
			addTarget(e.Target)
		}
	}
	for _, a := range fs.Args() {
		t, err := canonicalTarget(a, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid target:", err)
			return 2
		}
		addTarget(t)
	}
	if len(targets) == 0 {
		fs.Usage()
		return 2
	}

	offers := make([]*Offer, len(probeSpecs))
	for i, spec := range probeSpecs {
		o, err := captureOffer(spec.Config())
		if err != nil {
			fmt.Fprintf(os.Stderr, "capturing the %s offer: %v\n", spec.ID, err)
			return 2
		}
		offers[i] = o
	}

	report := Report{
		SchemaVersion: schemaVersion,
		Tool:          Tool{Name: "hasr", Go: runtime.Version()},
		GeneratedAt:   time.Now().UTC().Truncate(time.Second),
		Targets:       []Target{},
	}
	failed := false
	for _, target := range targets {
		t := scanTarget(target, offers, *timeout)
		if len(t.Summary.VersionsAccepted) == 0 {
			failed = true
		}
		report.Targets = append(report.Targets, t)
	}

	var err error
	if *table {
		err = printTable(os.Stdout, report)
	} else {
		err = printJSON(os.Stdout, report)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "output error:", err)
		return 2
	}
	if failed {
		return 1
	}
	return 0
}

// canonicalName resolves the host's CNAME chain (an ordinary DNS lookup) and
// returns its end, or "" for an IP address, a host without a CNAME, or a failed lookup.
func canonicalName(host string, timeout time.Duration) string {
	if isIP(host) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cname, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err != nil {
		return ""
	}
	cname = normalizeHost(cname)
	if cname == normalizeHost(host) {
		return ""
	}
	return cname
}

func normalizeHost(h string) string { return strings.ToLower(strings.TrimSuffix(h, ".")) }

func scanTarget(target string, offers []*Offer, timeout time.Duration) Target {
	now := time.Now().UTC().Truncate(time.Second)
	t := Target{Target: target, ScannedAt: now, Probes: []Probe{}, Certificates: []Certificate{}}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Error = "target must be host:port: " + err.Error()
		t.Summary = summarize(nil)
		t.Summary.KeyExchangeReasons = []string{"invalid target, nothing scanned"}
		t.Summary.Complete = false
		return t
	}

	t.CanonicalName = canonicalName(host, timeout)

	seen := map[string]bool{}
	for i, spec := range probeSpecs {
		p, chain := runProbe(spec, offers[i], target, timeout)
		if len(chain) > 0 {
			ref := certRef(chain[0])
			p.Negotiated.CertificateRef = ref
			if !seen[ref] {
				seen[ref] = true
				t.Certificates = append(t.Certificates, describeCertificate(chain, host, now))
			}
		}
		t.Probes = append(t.Probes, p)
	}
	settleClosed(t.Probes)
	t.Probes = append(t.Probes, notTested...)
	t.Summary = summarize(t.Probes)
	return t
}
