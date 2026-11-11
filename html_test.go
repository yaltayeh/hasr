package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestHeadline(t *testing.T) {
	cases := []struct {
		c      Completeness
		counts map[string]int
		want   string
	}{
		{Completeness{Mapped: 5, Assessed: 3, NotAssessed: 2}, map[string]int{statusAtRisk: 1, statusUnknown: 1},
			"1 of 3 assessed TLS endpoints is at risk. 1 has unknown priority. 2 mapped TLS endpoints could not be assessed."},
		{Completeness{Mapped: 2, Assessed: 2}, map[string]int{statusAtRisk: 2},
			"2 of 2 assessed TLS endpoints are at risk."},
		{Completeness{Mapped: 1, Assessed: 1, NotAssessed: 1, NeedsOwnerInput: 1}, map[string]int{},
			"None of the 1 assessed TLS endpoint is at risk. 1 mapped TLS endpoint could not be assessed. 1 scanned target needs owner input."},
		{Completeness{Mapped: 1, MappedNotScanned: 1}, map[string]int{},
			"No mapped target was fully assessed. 1 mapped target was not scanned."},
	}
	for _, tc := range cases {
		if got := headline(RiskReport{Completeness: tc.c}, tc.counts); got != tc.want {
			t.Errorf("headline = %q, want %q", got, tc.want)
		}
	}
}

// The first screen, the tooltips and the glossary, the in-page circular, and the
// summary print that works without the script.
func TestHTMLStructure(t *testing.T) {
	scan := Report{SchemaVersion: schemaVersion, Targets: []Target{classical13("a.example:443"), hybridSrv("b.example:443")}}
	mapping := []MappingEntry{
		{Target: "a.example:443", System: "A", DataClassification: "Secret", ThirdParty: "in-house"},
		{Target: "b.example:443", System: "B", DataClassification: "Secret", ThirdParty: "in-house"},
	}
	// b is hybrid with a margin above 0: "Mitigated", with its qualifier under the badge.
	r := buildReport(scan, Inputs{MappingFile: "m.csv", ScanFile: "s.json", PolicyFile: "p.json"}, mapping, fullPolicy(), time.Unix(0, 0))
	var b bytes.Buffer
	if err := writeHTML(&b, r, scan.Targets); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, want := range []string{
		`<h1>Hasr · <a href="#sama">SAMA Circular 482021280</a> · `,
		`<p class="headline">1 of 2 assessed TLS endpoints is at risk.</p>`,
		`<th>Target</th><th>System</th><th>Status`,
		`<tr class="rowdetail">`, `id="sama"`, `id="sama-clause-2"`, `href="#sama-clause-2"`, `id="glossary"`,
		`id="print-summary"`, `id="print-full"`, `Clause coverage`,
		`html:not(.print-full) #appendix{display:none}`,
		"the scan shows today",
		`Mitigated</span><span class="note">for PQ-capable clients</span>`,
		`@bottom-left{content:"Hasr · SAMA Circular 482021280 · `, `counter(pages)`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Every term with an ⓘ is in the glossary, and the glossary lists every entry once.
	for _, g := range glossary {
		if strings.Count(page, `<dt id="g-`+g.ID+`">`) != 1 {
			t.Errorf("glossary entry %s missing or repeated", g.ID)
		}
	}
	// Written once: the circular's title, and the translation note.
	for _, once := range []string{circular.Title, "Unofficial translation by the author"} {
		if n := strings.Count(page, once); n != 1 {
			t.Errorf("%q appears %d times, want once", once, n)
		}
	}
	for _, bad := range []string{"1 targets", "the scan show today"} {
		if strings.Contains(page, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
}

// A vendor endpoint without Y whose X alone exceeds Z: at risk on a lower
// bound, flagged, listed under Missing values; the scope line and the
// defaults note are on the page.
func TestHTMLLowerBound(t *testing.T) {
	scan := Report{SchemaVersion: schemaVersion, Targets: []Target{classical13("v.example:443")}}
	mapping := []MappingEntry{{Target: "v.example:443", System: "V", DataClassification: "Secret", ThirdParty: "Vendor Co"}}
	r := buildReport(scan, Inputs{MappingFile: "m.csv", ScanFile: "s.json", PolicyFile: "p.json"}, mapping, fullPolicy(), time.Unix(0, 0))
	if a := r.Assets[0]; a.Mosca.Status != statusAtRisk || !a.Mosca.MarginIsLowerBound || a.Mosca.Flag != "Y unknown: ask vendor" {
		t.Fatalf("mosca = %+v", a.Mosca)
	}
	var b bytes.Buffer
	if err := writeHTML(&b, r, scan.Targets); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, want := range []string{
		`≥ &#43;1</span>`, `<span class="ext" style="left:55.0%;width:45.0%"></span>`, `X 10 · Y ? · Z 9`, `Lower bound: Y ≥ 0`,
		`<span class="tag c-unk flag">Y unknown: ask vendor</span>`,
		`X + Y &gt; Z (1 with Y unknown)`, `target needs a value from its vendor (Y)`, `id="missing-entry-values"`,
		`<strong>Scope: TLS endpoints only.</strong>`, `TLS targets in the mapping file, assessed`,
		`<strong>What these defaults imply.</strong> With X for Top Secret and Secret and Z = 9, X is already larger than Z.`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestDefaultsNote(t *testing.T) {
	p := fullPolicy() // X: 25, 10, 5, 0; Z: 9
	if got := defaultsNote(p); !strings.HasPrefix(got, "With X for Top Secret and Secret and Z = 9,") {
		t.Errorf("note = %q", got)
	}
	p.ClassificationLevels[0].ShelfLife = sourced(10)
	if got := defaultsNote(p); !strings.HasPrefix(got, "With X = 10 for Top Secret and Secret and Z = 9,") {
		t.Errorf("note = %q", got)
	}
	p.Z.Years = f(30)
	if got := defaultsNote(p); got != "" {
		t.Errorf("no level above Z, note = %q", got)
	}
}
