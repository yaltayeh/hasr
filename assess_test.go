package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func f(v float64) *float64 { return &v }

// scanned builds a scan target from probes, with its summary computed.
func scanned(target string, probes ...Probe) Target {
	return Target{Target: target, Probes: probes, Certificates: []Certificate{}, Summary: summarize(probes)}
}

var (
	hybridSrv = func(target string) Target {
		return scanned(target, acc("default", t13, aes13, mlkem), acc("hybrid_only", t13, aes13, mlkem),
			acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
			rej("tls11_only"), rej("tls10_only"), rej("tls12_weak"))
	}
	classical13 = func(target string) Target {
		return scanned(target, acc("default", t13, aes13, x25519), rej("hybrid_only"),
			acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
			rej("tls11_only"), rej("tls10_only"), rej("tls12_weak"))
	}
	noTLS13 = func(target string) Target {
		return scanned(target, acc("default", t12, ecdhe, x25519), rej("hybrid_only"),
			acc("classical_only", t12, ecdhe, x25519), acc("max_tls12", t12, ecdhe, x25519),
			acc("tls11_only", t11, cbc, x25519), acc("tls10_only", t10, cbc, x25519), acc("tls12_weak", t12, rsaKex, 0))
	}
	unreachable = func(target string) Target {
		return scanned(target, er("default"), er("hybrid_only"), er("classical_only"), er("max_tls12"),
			er("tls11_only"), er("tls10_only"), er("tls12_weak"))
	}
)

// ndmoPolicy has the NDMO labels and no values, like a policy file with nulls.
func ndmoPolicy() Policy {
	return Policy{ClassificationLevels: []ClassificationLevel{
		{Label: "Top Secret"}, {Label: "Secret"}, {Label: "Restricted"}, {Label: "Public"},
	}}
}

func sourced(v float64) Sourced { return Sourced{Years: f(v), Source: "test source"} }

func fullPolicy() Policy {
	p := ndmoPolicy()
	for i, x := range []float64{25, 10, 5, 0} { // Top Secret, Secret, Restricted, Public
		p.ClassificationLevels[i].ShelfLife = sourced(x)
	}
	p.MigrationYearsDefault = MigrationDefaults{AlreadyHybrid: sourced(0), TLS13Classical: sourced(1), NoTLS13: sourced(3), ManagedTLSPolicy: sourced(0.5)}
	p.MigrationYearsDefault.TLS13Classical.Assumption = true
	p.Z = ZValue{Date: "2035-01-01", Source: "test value", Years: f(9)}
	return p
}

func TestAssessMosca(t *testing.T) {
	pol := fullPolicy()
	tests := []struct {
		name       string
		target     Target
		entry      MappingEntry
		pol        Policy
		status     string
		margin     *float64
		noteSubstr string
	}{
		{"classification default X + scan default Y: at risk", noTLS13("a:1"),
			MappingEntry{DataClassification: "Secret", ThirdParty: "in-house"}, pol, statusAtRisk, f(10 + 3 - 9), ""},
		{"margin exactly 0 is not at risk (X + Y > Z is strict)", classical13("a:1"),
			MappingEntry{DataClassification: "Secret", ThirdParty: "In-House", DataShelfLifeYears: f(8)}, pol, statusNotAtRisk, f(8 + 1 - 9), ""},
		{"overrides beat defaults", classical13("a:1"),
			MappingEntry{DataClassification: "Secret", ThirdParty: "in-house", DataShelfLifeYears: f(2), MigrationYears: f(4)}, pol, statusNotAtRisk, f(2 + 4 - 9), ""},
		{"vendor without Y: unknown, never guessed", classical13("a:1"),
			MappingEntry{DataClassification: "Secret", ThirdParty: "Vendor X"}, pol, statusUnknown, nil, "never guessed"},
		{"vendor with Y given: computed", classical13("a:1"),
			MappingEntry{DataClassification: "Secret", ThirdParty: "Vendor X", MigrationYears: f(5)}, pol, statusAtRisk, f(10 + 5 - 9), ""},
		{"third_party not stated: unknown", classical13("a:1"),
			MappingEntry{DataClassification: "Secret"}, pol, statusUnknown, nil, "third_party not stated"},
		{"no classification, no X: unknown", classical13("a:1"),
			MappingEntry{ThirdParty: "in-house"}, pol, statusUnknown, nil, "X unknown"},
		{"Z not set: unknown", classical13("a:1"),
			MappingEntry{DataClassification: "Secret", ThirdParty: "in-house"}, ndmoPolicy(), statusUnknown, nil, "Z unknown"},
		{"hybrid that accepts classical: mitigated, even with a positive margin", hybridSrv("a:1"),
			MappingEntry{DataClassification: "Top Secret", ThirdParty: "in-house"}, pol, statusMitigated, f(25 + 0 - 9), "residual risk depends on client support"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mo := assessMosca(tc.target, &tc.entry, tc.pol)
			if mo.Status != tc.status {
				t.Errorf("status = %s, want %s (notes %q)", mo.Status, tc.status, mo.Notes)
			}
			switch {
			case tc.margin == nil && mo.Margin != nil:
				t.Errorf("margin = %g, want unknown", *mo.Margin)
			case tc.margin != nil && (mo.Margin == nil || *mo.Margin != *tc.margin):
				t.Errorf("margin = %v, want %g", mo.Margin, *tc.margin)
			}
			if mo.YSource == "default for TLS 1.3, classical key exchange" && !mo.YAssumption {
				t.Error("an assumption default must be marked as such")
			}
			if (mo.Status == statusMitigated) != (mo.MarginScope == "clients without ML-KEM only") {
				t.Errorf("status %s with margin scope %q", mo.Status, mo.MarginScope)
			}
			if tc.noteSubstr != "" && !strings.Contains(strings.Join(mo.Notes, " | "), tc.noteSubstr) {
				t.Errorf("notes %q lack %q", mo.Notes, tc.noteSubstr)
			}
		})
	}
}

func TestBuildReportSections(t *testing.T) {
	scan := Report{SchemaVersion: schemaVersion, Targets: []Target{
		classical13("lab:1"), // mapped, complete
		noTLS13("lab:2"),     // mapped, complete, at risk
		hybridSrv("own:443"), // not mapped -> needs owner input
		unreachable("lab:9"), // mapped, unreachable -> not assessed
	}}
	scan.Targets[0].Probes = append(scan.Targets[0].Probes, notTested...)
	mapping := []MappingEntry{
		{Target: "lab:1", System: "One", DataClassification: "Restricted", ThirdParty: "in-house"},
		{Target: "lab:2", System: "Two", DataClassification: "Top Secret", ThirdParty: "in-house"},
		{Target: "lab:9", System: "Nine", DataClassification: "Public", ThirdParty: "in-house"},
		{Target: "lab:7", System: "Seven"}, // mapped, not scanned
	}
	r := buildReport(scan, Inputs{}, mapping, fullPolicy(), time.Unix(0, 0))

	targets := func(as []Asset) (out []string) {
		for _, a := range as {
			out = append(out, a.Target)
		}
		return
	}
	if got := strings.Join(targets(r.Assets), ","); got != "lab:2,lab:1" {
		t.Errorf("assets in priority order = %s, want lab:2,lab:1", got)
	}
	if got := strings.Join(targets(r.NeedsOwnerInput), ","); got != "own:443" {
		t.Errorf("needs owner input = %s", got)
	}
	if got := strings.Join(targets(r.NotAssessed), ","); got != "lab:9" {
		t.Errorf("not assessed = %s", got)
	}
	if len(r.MappedNotScanned) != 1 || r.MappedNotScanned[0].Target != "lab:7" {
		t.Errorf("mapped not scanned = %+v", r.MappedNotScanned)
	}
	want := Completeness{Mapped: 4, Assessed: 2, MappedNotScanned: 1, NotAssessed: 1, NeedsOwnerInput: 1, Scanned: 4}
	if r.Completeness != want {
		t.Errorf("completeness = %+v, want %+v", r.Completeness, want)
	}
	if len(r.NotTested) != len(notTested)+1 {
		t.Errorf("not tested = %d limits, want %d", len(r.NotTested), len(notTested)+1)
	}
	if r.NotAssessed[0].Mosca.Status != statusUnknown {
		t.Errorf("not assessed must never get a priority: %s", r.NotAssessed[0].Mosca.Status)
	}
	if r.Assets[0].Mosca.Status != statusAtRisk {
		t.Errorf("lab:2 status = %s, want at_risk", r.Assets[0].Mosca.Status)
	}
}

func TestFindings(t *testing.T) {
	got := findings(noTLS13("x:1"))
	var lines []string
	for _, fd := range got {
		lines = append(lines, fd.Area+": "+fd.Finding+" -> "+fd.Action)
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"key_exchange: No TLS 1.3",
		"legacy: Accepts TLS 1.0 -> Disable TLS 1.0.",
		"legacy: Accepts TLS 1.1 -> Disable TLS 1.1.",
		"legacy: Accepts weak suite TLS_RSA_WITH_AES_128_GCM_SHA256 (RSA key transport, no forward secrecy) -> Remove RSA key transport (TLS_RSA_*) suites.",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("findings lack %q; got:\n%s", want, all)
		}
	}
}

func TestHTMLEscapesAndIsSelfContained(t *testing.T) {
	scan := Report{SchemaVersion: schemaVersion, Targets: []Target{classical13("lab:1")}}
	mapping := []MappingEntry{{Target: "lab:1", System: `<script>alert("x")</script>`, Owner: `"><img src=x onerror=alert(1)>`, ThirdParty: "in-house"}}
	r := buildReport(scan, Inputs{MappingFile: "m.csv", ScanFile: "s.json", PolicyFile: "p.json"}, mapping, ndmoPolicy(), time.Unix(0, 0))
	var b bytes.Buffer
	if err := writeHTML(&b, r); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	// Self-contained: nothing is loaded from elsewhere. Plain links to sources are allowed.
	for _, bad := range []string{`<script>alert`, `<img src=x`, `<script src`, `<link `, `src="http`, `url(http`, `@import`} {
		if strings.Contains(page, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	for _, want := range []string{"Raising the level of operational resilience to address quantum computing risks",
		"Accordingly, financial institutions are required to take the following actions:", "<dt>Distribution</dt>"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, unwanted := range []string{"Royal Decree", "CFC@SAMA.GOV.SA"} {
		if strings.Contains(page, unwanted) {
			t.Errorf("page prints %q, which is not to be printed", unwanted)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Error("CSV content was not escaped")
	}
}
