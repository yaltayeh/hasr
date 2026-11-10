package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"time"
)

// defaultPolicyFile is read when --policy is not given. No values are built
// into the code (DECISIONS.md, "Policy values").
const defaultPolicyFile = "policy/default.json"

// Policy holds the report's values that are not per target: the classification
// levels with their default X, the default Y per scan category, and Z.
// Every value carries the source text the report prints next to it.
type Policy struct {
	ClassificationLevels  []ClassificationLevel `json:"classification_levels"`
	MigrationYearsDefault MigrationDefaults     `json:"migration_years_default"`
	Z                     ZValue                `json:"z"`
}

// Sourced is a number of years with where it comes from.
type Sourced struct {
	Years  *float64 `json:"years"` // null = not set
	Source string   `json:"source"`
	Links  []string `json:"links,omitempty"` // https links to the source documents
	// Assumption marks a value the report shows as "assumption; override per entry".
	Assumption bool `json:"assumption,omitempty"`
}

type ClassificationLevel struct {
	Label     string  `json:"label"`
	ShelfLife Sourced `json:"shelf_life"` // default X for this level
}

// MigrationDefaults are the default Y per scan category.
type MigrationDefaults struct {
	AlreadyHybrid  Sourced `json:"already_hybrid"`
	TLS13Classical Sourced `json:"tls13_classical"`
	NoTLS13        Sourced `json:"no_tls13"`
	// ManagedTLSPolicy applies when a cloud record shows the endpoint's TLS
	// policy is a managed setting (DECISIONS.md, "Cloud discovery (AWS)").
	ManagedTLSPolicy Sourced `json:"managed_tls_policy"`
}

// ZValue is the date of the quantum threat or a regulatory deadline (Mosca's
// Z); Years is computed from it at report time.
type ZValue struct {
	Date   string   `json:"date"` // YYYY-MM-DD
	Source string   `json:"source"`
	Links  []string `json:"links,omitempty"` // https links to the source documents
	// Years from the report date to Date, rounded to 0.01. Computed, never read from the file.
	Years *float64 `json:"years_from_report_date,omitempty"`
}

// loadPolicy reads and validates a policy file, then computes Z for the report date.
func loadPolicy(path string, reportDate time.Time) (Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer f.Close()
	var p Policy
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	if p.Z.Years != nil {
		return Policy{}, fmt.Errorf("%s: z.years_from_report_date is computed from z.date; remove it", path)
	}
	if err := p.validate(); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.resolveZ(reportDate); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

func (p Policy) validate() error {
	if len(p.ClassificationLevels) == 0 {
		return errors.New("classification_levels is empty")
	}
	seen := map[string]bool{}
	for _, l := range p.ClassificationLevels {
		key := strings.ToLower(strings.TrimSpace(l.Label))
		if key == "" {
			return errors.New("a classification level has an empty label")
		}
		if seen[key] {
			return fmt.Errorf("classification level %q appears twice", l.Label)
		}
		seen[key] = true
		if err := l.ShelfLife.check("shelf_life of " + l.Label); err != nil {
			return err
		}
	}
	m := p.MigrationYearsDefault
	for name, v := range map[string]Sourced{
		"migration_years_default.already_hybrid":     m.AlreadyHybrid,
		"migration_years_default.tls13_classical":    m.TLS13Classical,
		"migration_years_default.no_tls13":           m.NoTLS13,
		"migration_years_default.managed_tls_policy": m.ManagedTLSPolicy,
	} {
		if err := v.check(name); err != nil {
			return err
		}
	}
	if p.Z.Date != "" && strings.TrimSpace(p.Z.Source) == "" {
		return errors.New("z.source is required when z.date is set: the report prints it")
	}
	return checkLinks("z", p.Z.Links)
}

// checkLinks accepts only absolute https URLs; the report renders them as links.
func checkLinks(name string, links []string) error {
	for _, l := range links {
		u, err := url.Parse(l)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%s: link %q must be an absolute https URL", name, l)
		}
	}
	return nil
}

func (s Sourced) check(name string) error {
	if err := checkLinks(name, s.Links); err != nil {
		return err
	}
	switch {
	case s.Years == nil && s.Assumption:
		return fmt.Errorf("%s: assumption is set but years is not", name)
	case s.Years == nil:
		return nil
	case *s.Years < 0 || math.IsNaN(*s.Years) || math.IsInf(*s.Years, 0):
		return fmt.Errorf("%s: years must be a non-negative number", name)
	case strings.TrimSpace(s.Source) == "":
		return fmt.Errorf("%s: source is required: every value carries its source", name)
	}
	return nil
}

// resolveZ converts z.date into years from the report date: days / 365.25,
// rounded to 0.01. PROVISIONAL conversion.
func (p *Policy) resolveZ(reportDate time.Time) error {
	if p.Z.Date == "" {
		return nil
	}
	d, err := time.Parse("2006-01-02", p.Z.Date)
	if err != nil {
		return fmt.Errorf("z.date %q is not YYYY-MM-DD", p.Z.Date)
	}
	from := reportDate.UTC().Truncate(24 * time.Hour)
	years := round2(d.Sub(from).Hours() / 24 / 365.25)
	p.Z.Years = &years
	return nil
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func (p Policy) labels() []string {
	out := make([]string, len(p.ClassificationLevels))
	for i, l := range p.ClassificationLevels {
		out[i] = l.Label
	}
	return out
}

func (p Policy) shelfLife(label string) Sourced {
	for _, l := range p.ClassificationLevels {
		if strings.EqualFold(l.Label, label) {
			return l.ShelfLife
		}
	}
	return Sourced{}
}

// Scan categories for the default Y (DECISIONS.md, "Mosca: X, Y, Z").
const (
	catAlreadyHybrid  = "already_hybrid"
	catTLS13Classical = "tls13_classical"
	catNoTLS13        = "no_tls13"
	catManagedTLS     = "managed_tls_policy"
)

var categoryLabels = map[string]string{
	catAlreadyHybrid:  "already hybrid",
	catTLS13Classical: "TLS 1.3, classical key exchange",
	catNoTLS13:        "no TLS 1.3",
	catManagedTLS:     "managed TLS policy (cloud)",
}

func (p Policy) migrationDefault(category string) Sourced {
	switch category {
	case catAlreadyHybrid:
		return p.MigrationYearsDefault.AlreadyHybrid
	case catTLS13Classical:
		return p.MigrationYearsDefault.TLS13Classical
	case catNoTLS13:
		return p.MigrationYearsDefault.NoTLS13
	case catManagedTLS:
		return p.MigrationYearsDefault.ManagedTLSPolicy
	}
	return Sourced{}
}

// missingValues lists the policy values that are not set.
func (p Policy) missingValues() []string {
	var m []string
	if p.Z.Years == nil {
		m = append(m, "Z")
	}
	var xs []string
	for _, l := range p.ClassificationLevels {
		if l.ShelfLife.Years == nil {
			xs = append(xs, l.Label)
		}
	}
	if len(xs) > 0 {
		m = append(m, "default X for "+strings.Join(xs, ", "))
	}
	var ys []string
	for _, c := range []string{catAlreadyHybrid, catTLS13Classical, catNoTLS13, catManagedTLS} {
		if p.migrationDefault(c).Years == nil {
			ys = append(ys, categoryLabels[c])
		}
	}
	if len(ys) > 0 {
		m = append(m, "default Y for "+strings.Join(ys, ", "))
	}
	return m
}
