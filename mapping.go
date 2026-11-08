package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
)

// mappingColumns are the mapping CSV's columns (DECISIONS.md, "Mapping file").
var mappingColumns = []string{"target", "system", "service", "owner", "data_classification",
	"data_shelf_life_years", "migration_years", "third_party", "constraints"}

// MappingEntry is one row of the mapping CSV: the human input for one target.
type MappingEntry struct {
	Target             string   `json:"target"`
	System             string   `json:"system"`
	Service            string   `json:"service"`
	Owner              string   `json:"owner"`
	DataClassification string   `json:"data_classification"`
	DataShelfLifeYears *float64 `json:"data_shelf_life_years"` // X override; null = not given
	MigrationYears     *float64 `json:"migration_years"`       // Y override; null = not given
	ThirdParty         string   `json:"third_party"`
	Constraints        string   `json:"constraints"`
}

// readMapping parses the mapping CSV at path. If labels is non-nil,
// data_classification must be one of them (case-insensitive) and is stored as
// the canonical label; with nil labels it is not checked (hasr scan --targets
// needs only the target column).
func readMapping(path string, labels []string) ([]MappingEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := parseMapping(f, labels)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return entries, nil
}

func parseMapping(r io.Reader, labels []string) ([]MappingEntry, error) {
	cr := csv.NewReader(r) // every row must have as many fields as the header
	header, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("empty file: a header row is required")
	}
	if err != nil {
		return nil, err
	}
	header[0] = strings.TrimPrefix(header[0], "\uFEFF") // byte-order mark from spreadsheet exports
	col := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		if !contains(mappingColumns, h) {
			return nil, fmt.Errorf("unknown column %q (columns are: %s)", h, strings.Join(mappingColumns, ", "))
		}
		if _, dup := col[h]; dup {
			return nil, fmt.Errorf("column %q appears twice", h)
		}
		col[h] = i
	}
	for _, c := range mappingColumns {
		if _, ok := col[c]; !ok {
			return nil, fmt.Errorf("missing column %q", c)
		}
	}

	entries := []MappingEntry{}
	seen := map[string]int{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(0)
		get := func(name string) string { return strings.TrimSpace(rec[col[name]]) }
		if strings.TrimSpace(strings.Join(rec, "")) == "" {
			continue // a row of empty cells
		}

		e := MappingEntry{
			Target:             get("target"),
			System:             get("system"),
			Service:            get("service"),
			Owner:              get("owner"),
			DataClassification: get("data_classification"),
			ThirdParty:         get("third_party"),
			Constraints:        get("constraints"),
		}
		if err := checkTarget(e.Target); err != nil {
			return nil, fmt.Errorf("line %d: %v", line, err)
		}
		if prev, dup := seen[e.Target]; dup {
			return nil, fmt.Errorf("line %d: target %s is already on line %d", line, e.Target, prev)
		}
		seen[e.Target] = line

		if labels != nil && e.DataClassification != "" {
			canon := ""
			for _, l := range labels {
				if strings.EqualFold(l, e.DataClassification) {
					canon = l
				}
			}
			if canon == "" {
				return nil, fmt.Errorf("line %d: data_classification %q is not one of: %s", line, e.DataClassification, strings.Join(labels, ", "))
			}
			e.DataClassification = canon
		}
		if e.DataShelfLifeYears, err = parseYears(get("data_shelf_life_years")); err != nil {
			return nil, fmt.Errorf("line %d: data_shelf_life_years: %v", line, err)
		}
		if e.MigrationYears, err = parseYears(get("migration_years")); err != nil {
			return nil, fmt.Errorf("line %d: migration_years: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// checkTarget requires host:port with a numeric port in 1-65535.
func checkTarget(t string) error {
	host, port, err := net.SplitHostPort(t)
	if err != nil {
		return fmt.Errorf("target %q must be host:port", t)
	}
	if host == "" {
		return fmt.Errorf("target %q has no host", t)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("target %q has an invalid port", t)
	}
	return nil
}

// parseYears reads an optional, non-negative number of years. Empty means not given.
func parseYears(s string) (*float64, error) {
	if s == "" {
		return nil, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, fmt.Errorf("%q is not a non-negative number of years", s)
	}
	return &v, nil
}
