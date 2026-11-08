package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDefaultPolicyFile checks the committed policy/default.json.
func TestDefaultPolicyFile(t *testing.T) {
	reportDate := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	p, err := loadPolicy(defaultPolicyFile, reportDate)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.labels(), ","); got != "Top Secret,Secret,Restricted,Public" {
		t.Errorf("labels = %s", got)
	}
	if m := p.missingValues(); len(m) != 0 {
		t.Errorf("missing values: %v", m)
	}
	// 2026-11-08 to 2030-12-31 is 1514 days; 1514 / 365.25 = 4.145 -> 4.15.
	if p.Z.Years == nil || *p.Z.Years != 4.15 {
		t.Errorf("Z = %v, want 4.15", p.Z.Years)
	}
	for _, l := range p.ClassificationLevels {
		if l.ShelfLife.Source == "" {
			t.Errorf("X for %s has no source", l.Label)
		}
	}
	if len(p.Z.Links) != 2 {
		t.Errorf("Z links = %v, want the NIST and ENISA links", p.Z.Links)
	}
	m := p.MigrationYearsDefault
	if !m.TLS13Classical.Assumption || !m.NoTLS13.Assumption {
		t.Error("both scan-derived Y defaults must be marked as assumptions")
	}
}

func TestPolicyValidation(t *testing.T) {
	cases := []struct{ name, json, want string }{
		{"value without source", `{"classification_levels":[{"label":"A","shelf_life":{"years":3}}]}`, "source is required"},
		{"negative", `{"classification_levels":[{"label":"A","shelf_life":{"years":-1,"source":"s"}}]}`, "non-negative"},
		{"assumption without value", `{"classification_levels":[{"label":"A","shelf_life":{"assumption":true}}]}`, "assumption is set"},
		{"duplicate label", `{"classification_levels":[{"label":"A","shelf_life":{}},{"label":"a","shelf_life":{}}]}`, "appears twice"},
		{"bad date", `{"classification_levels":[{"label":"A","shelf_life":{}}],"z":{"date":"31/12/2030","source":"s"}}`, "not YYYY-MM-DD"},
		{"Z without source", `{"classification_levels":[{"label":"A","shelf_life":{}}],"z":{"date":"2030-12-31"}}`, "z.source is required"},
		{"computed field in file", `{"classification_levels":[{"label":"A","shelf_life":{}}],"z":{"date":"2030-12-31","source":"s","years_from_report_date":4}}`, "computed"},
		{"javascript link", `{"classification_levels":[{"label":"A","shelf_life":{}}],"z":{"date":"2030-12-31","source":"s","links":["javascript:alert(1)"]}}`, "absolute https URL"},
		{"http link", `{"classification_levels":[{"label":"A","shelf_life":{"years":1,"source":"s","links":["http://example.com"]}}]}`, "absolute https URL"},
		{"unknown field", `{"classification_levels":[{"label":"A","shelf_life":{}}],"zz":1}`, "unknown field"},
	}
	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "p.json")
			if err := os.WriteFile(path, []byte(tc.json), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadPolicy(path, time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
