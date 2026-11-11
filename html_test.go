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
			"1 of 3 assessed assets is at risk. 1 has unknown priority. 2 mapped assets could not be assessed."},
		{Completeness{Mapped: 2, Assessed: 2}, map[string]int{statusAtRisk: 2},
			"2 of 2 assessed assets are at risk."},
		{Completeness{Mapped: 1, Assessed: 1, NotAssessed: 1, NeedsOwnerInput: 1}, map[string]int{},
			"None of the 1 assessed asset is at risk. 1 mapped asset could not be assessed. 1 scanned target needs owner input."},
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
		`<p class="headline">1 of 2 assessed assets is at risk.</p>`,
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
