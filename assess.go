package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const reportSchemaVersion = "0.1"

// RiskReport is what `hasr report` writes as JSON and renders as HTML.
// PROVISIONAL: the schema is not frozen.
type RiskReport struct {
	Kind          string       `json:"kind"` // "hasr-report"
	SchemaVersion string       `json:"schema_version"`
	Tool          Tool         `json:"tool"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Inputs        Inputs       `json:"inputs"`
	Policy        Policy       `json:"policy"`
	MissingValues []string     `json:"missing_values"` // policy values not set yet
	Completeness  Completeness `json:"completeness"`

	// Assets are mapped, scanned and completely assessed, in priority order.
	Assets []Asset `json:"assets"`
	// NeedsOwnerInput were scanned but are not in the mapping file.
	NeedsOwnerInput []Asset `json:"needs_owner_input"`
	// MappedNotScanned are in the mapping file but were not scanned.
	MappedNotScanned []MappingEntry `json:"mapped_not_scanned"`
	// NotAssessed are mapped and scanned but unreachable or incomplete.
	NotAssessed []Asset `json:"not_assessed"`
	// NotTested are the scanner's stated limits.
	NotTested []Limit `json:"not_tested"`
}

type Inputs struct {
	ScanFile          string    `json:"scan_file"`
	ScanGeneratedAt   time.Time `json:"scan_generated_at"`
	ScanSchemaVersion string    `json:"scan_schema_version"`
	ScanTool          Tool      `json:"scan_tool"`
	MappingFile       string    `json:"mapping_file"`
	PolicyFile        string    `json:"policy_file"` // empty = built-in defaults
}

type Completeness struct {
	Mapped           int `json:"mapped"`   // rows in the mapping file
	Assessed         int `json:"assessed"` // mapped, scanned and complete
	MappedNotScanned int `json:"mapped_not_scanned"`
	NotAssessed      int `json:"not_assessed"`
	NeedsOwnerInput  int `json:"needs_owner_input"`
	Scanned          int `json:"scanned"`
}

type Asset struct {
	Target           string        `json:"target"`
	Mapping          *MappingEntry `json:"mapping,omitempty"`
	ScannedAt        time.Time     `json:"scanned_at"`
	KeyExchange      string        `json:"key_exchange"`
	Legacy           string        `json:"legacy"`
	VersionsAccepted []string      `json:"versions_accepted"`
	// Problem says why the asset is not assessed (invalid target, inconclusive probes).
	Problem      string        `json:"problem,omitempty"`
	Mosca        Mosca         `json:"mosca"`
	Findings     []Finding     `json:"findings"`
	Certificates []Certificate `json:"certificates"`
}

// Mosca is X + Y > Z for one asset. A nil value is unknown.
type Mosca struct {
	X       *float64 `json:"x"`
	XSource string   `json:"x_source"`
	Y       *float64 `json:"y"`
	YSource string   `json:"y_source"`
	// YAssumption: Y is a default the policy marks as an assumption.
	YAssumption bool     `json:"y_assumption"`
	Z           *float64 `json:"z"`
	Margin      *float64 `json:"margin"` // X + Y - Z
	// MarginScope says whom the margin applies to, when not all clients.
	MarginScope string   `json:"margin_scope,omitempty"`
	Status      string   `json:"status"` // at_risk | not_at_risk | mitigated_pq_clients | unknown
	Notes       []string `json:"notes"`
}

const (
	statusAtRisk    = "at_risk"
	statusNotAtRisk = "not_at_risk"
	statusMitigated = "mitigated_pq_clients"
	statusUnknown   = "unknown"
)

// Finding is one observation with its recommended action.
type Finding struct {
	Area    string `json:"area"` // key_exchange | legacy | certificate
	Finding string `json:"finding"`
	Action  string `json:"action"`
}

// Limit is something the scanner did not test.
type Limit struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

func buildReport(scan Report, inputs Inputs, mapping []MappingEntry, pol Policy, now time.Time) RiskReport {
	r := RiskReport{
		Kind:             "hasr-report",
		SchemaVersion:    reportSchemaVersion,
		GeneratedAt:      now,
		Inputs:           inputs,
		Policy:           pol,
		MissingValues:    pol.missingValues(),
		Assets:           []Asset{},
		NeedsOwnerInput:  []Asset{},
		MappedNotScanned: []MappingEntry{},
		NotAssessed:      []Asset{},
		NotTested:        []Limit{},
	}
	byTarget := map[string]*MappingEntry{}
	for i := range mapping {
		byTarget[mapping[i].Target] = &mapping[i]
	}
	scanned := map[string]bool{}
	seenLimit := map[string]bool{}

	for _, t := range scan.Targets {
		scanned[t.Target] = true
		m := byTarget[t.Target]
		a := assessTarget(t, m, pol)
		switch {
		case m == nil:
			r.NeedsOwnerInput = append(r.NeedsOwnerInput, a)
		case a.Problem != "":
			r.NotAssessed = append(r.NotAssessed, a)
		default:
			r.Assets = append(r.Assets, a)
		}
		for _, p := range t.Probes {
			if p.Result == resultNotTested && !seenLimit[p.ID] {
				seenLimit[p.ID] = true
				r.NotTested = append(r.NotTested, Limit{ID: p.ID, Detail: p.Detail})
			}
		}
	}
	if len(scan.Targets) > 0 {
		r.NotTested = append(r.NotTested, Limit{ID: "3des_rc4", Detail: unverifiedNote})
	}
	for _, m := range mapping {
		if !scanned[m.Target] {
			r.MappedNotScanned = append(r.MappedNotScanned, m)
		}
	}
	sortByPriority(r.Assets)

	r.Completeness = Completeness{
		Mapped:           len(mapping),
		Assessed:         len(r.Assets),
		MappedNotScanned: len(r.MappedNotScanned),
		NotAssessed:      len(r.NotAssessed),
		NeedsOwnerInput:  len(r.NeedsOwnerInput),
		Scanned:          len(scan.Targets),
	}
	return r
}

func assessTarget(t Target, m *MappingEntry, pol Policy) Asset {
	s := t.Summary
	a := Asset{
		Target:           t.Target,
		Mapping:          m,
		ScannedAt:        t.ScannedAt,
		KeyExchange:      s.KeyExchange,
		Legacy:           s.Legacy,
		VersionsAccepted: s.VersionsAccepted,
		Findings:         findings(t),
		Certificates:     t.Certificates,
	}
	switch {
	case t.Error != "":
		a.Problem = t.Error
	case len(s.VersionsAccepted) == 0:
		a.Problem = "unreachable: no probe accepted (" + strings.Join(s.InconclusiveProbes, ", ") + " ended in error)"
	case !s.Complete:
		a.Problem = "incomplete: " + strings.Join(s.InconclusiveProbes, ", ") + " ended in error"
	}
	switch {
	case m == nil:
		a.Mosca = Mosca{Status: statusUnknown, Notes: []string{"not in the mapping file: needs owner input"}}
	case a.Problem != "":
		a.Mosca = Mosca{Status: statusUnknown, Notes: []string{"not assessed: " + a.Problem}}
	default:
		a.Mosca = assessMosca(t, m, pol)
	}
	return a
}

// assessMosca applies DECISIONS.md "Mosca: X, Y, Z" and "What Mosca applies to".
func assessMosca(t Target, m *MappingEntry, pol Policy) Mosca {
	var mo Mosca
	mo.Notes = []string{}

	// X: per-entry override, else the classification's default.
	switch {
	case m.DataShelfLifeYears != nil:
		mo.X, mo.XSource = m.DataShelfLifeYears, "per entry (mapping file)"
	case m.DataClassification == "":
		mo.Notes = append(mo.Notes, "X unknown: no data_classification and no data_shelf_life_years")
	case pol.shelfLife(m.DataClassification).Years != nil:
		mo.X, mo.XSource = pol.shelfLife(m.DataClassification).Years, "default for "+m.DataClassification
	default:
		mo.Notes = append(mo.Notes, "X unknown: no default shelf life set for "+m.DataClassification)
	}

	// Y: per-entry override; else the scan-derived default, for in-house endpoints only.
	cat := migrationCategory(t)
	switch {
	case m.MigrationYears != nil:
		mo.Y, mo.YSource = m.MigrationYears, "per entry (mapping file)"
	case strings.TrimSpace(m.ThirdParty) == "":
		mo.Notes = append(mo.Notes, "Y unknown: third_party not stated; the scan-derived default applies only to in-house endpoints")
	case !isInHouse(m.ThirdParty):
		mo.Notes = append(mo.Notes, "Y unknown: operated by "+m.ThirdParty+"; a vendor's timeline is never guessed, set migration_years")
	case cat == "":
		mo.Notes = append(mo.Notes, "Y unknown: the scan gives no migration category")
	case pol.migrationDefault(cat).Years != nil:
		d := pol.migrationDefault(cat)
		mo.Y, mo.YSource, mo.YAssumption = d.Years, "default for "+categoryLabels[cat], d.Assumption
	default:
		mo.Notes = append(mo.Notes, "Y unknown: no default set for "+categoryLabels[cat])
	}

	// Z: one global value.
	mo.Z = pol.Z.Years
	if mo.Z == nil {
		mo.Notes = append(mo.Notes, "Z unknown: not set")
	}
	if mo.X != nil && mo.Y != nil && mo.Z != nil {
		margin := round2(*mo.X + *mo.Y - *mo.Z)
		mo.Margin = &margin
	}

	switch {
	case t.Summary.KeyExchange == "hybrid" && acceptsClassical(t):
		mo.Status = statusMitigated
		if mo.Margin != nil {
			// PQ-capable clients get hybrid key exchange; only the others carry this margin.
			mo.MarginScope = "clients without ML-KEM only"
		}
		mo.Notes = append([]string{"residual risk depends on client support: clients without post-quantum support still get classical key exchange"}, mo.Notes...)
	case t.Summary.KeyExchange == "hybrid":
		mo.Status = statusNotAtRisk
		mo.Notes = append([]string{"only hybrid key exchange was accepted"}, mo.Notes...)
	case mo.Margin == nil:
		mo.Status = statusUnknown
	case *mo.Margin > 0:
		mo.Status = statusAtRisk
	default:
		mo.Status = statusNotAtRisk
	}
	return mo
}

func isInHouse(thirdParty string) bool {
	return strings.EqualFold(strings.TrimSpace(thirdParty), "in-house")
}

// migrationCategory maps the scan to a default-Y category, or "" if it can't.
func migrationCategory(t Target) string {
	s := t.Summary
	switch {
	case s.KeyExchange == "hybrid":
		return catAlreadyHybrid
	case s.KeyExchange == "classical" && contains(s.VersionsAccepted, "TLS 1.3"):
		return catTLS13Classical
	case s.KeyExchange == "classical" && contains(s.KeyExchangeReasons, noTLS13Reason):
		return catNoTLS13
	}
	return ""
}

// acceptsClassical reports whether any accepted probe ended with a key
// exchange that is not hybrid (a classical group, or RSA key transport).
func acceptsClassical(t Target) bool {
	for _, p := range t.Probes {
		if p.Result != resultAccepted || p.Negotiated == nil {
			continue
		}
		if g := p.Negotiated.Group; g == nil || !hybridGroups[g.Codepoint] {
			return true
		}
	}
	return false
}

// sortByPriority: at risk (largest margin first), then unknown, then not at
// risk (largest margin first), then mitigated. PROVISIONAL order.
func sortByPriority(as []Asset) {
	rank := map[string]int{statusAtRisk: 0, statusUnknown: 1, statusNotAtRisk: 2, statusMitigated: 3}
	margin := func(a Asset) float64 {
		if a.Mosca.Margin == nil {
			return 0
		}
		return *a.Mosca.Margin
	}
	sort.SliceStable(as, func(i, j int) bool {
		ri, rj := rank[as[i].Mosca.Status], rank[as[j].Mosca.Status]
		if ri != rj {
			return ri < rj
		}
		if mi, mj := margin(as[i]), margin(as[j]); mi != mj {
			return mi > mj
		}
		return as[i].Target < as[j].Target
	})
}

// findings turns the scan into findings with a recommended action each.
// PROVISIONAL wording.
func findings(t Target) []Finding {
	s := t.Summary
	out := []Finding{}
	add := func(area, finding, action string) {
		out = append(out, Finding{Area: area, Finding: finding, Action: action})
	}

	switch {
	case s.KeyExchange == "classical" && contains(s.VersionsAccepted, "TLS 1.3"):
		add("key_exchange", "Classical key exchange only; TLS 1.3 is available",
			"Enable hybrid key exchange (X25519MLKEM768); this may need a TLS library upgrade.")
	case s.KeyExchange == "classical" && contains(s.KeyExchangeReasons, noTLS13Reason):
		add("key_exchange", "No TLS 1.3; classical key exchange only",
			"Enable TLS 1.3 first (protocol upgrade), then hybrid key exchange (X25519MLKEM768).")
	case s.KeyExchange == "hybrid" && acceptsClassical(t):
		add("key_exchange", "Hybrid key exchange available; classical key exchange still accepted",
			"No change now. Track client support for post-quantum key exchange before restricting classical key exchange.")
	}

	if contains(s.VersionsAccepted, "TLS 1.0") {
		add("legacy", "Accepts TLS 1.0", "Disable TLS 1.0.")
	}
	if contains(s.VersionsAccepted, "TLS 1.1") {
		add("legacy", "Accepts TLS 1.1", "Disable TLS 1.1.")
	}
	seen := map[string]bool{}
	for _, p := range t.Probes {
		if p.Result != resultAccepted || p.Negotiated == nil {
			continue
		}
		name := p.Negotiated.CipherSuite.Name
		why := weakSuiteReason(name)
		if why == "" || seen[name] {
			continue
		}
		seen[name] = true
		var actions []string
		if strings.HasPrefix(name, "TLS_RSA_WITH_") {
			actions = append(actions, "remove RSA key transport (TLS_RSA_*) suites")
		}
		if strings.Contains(name, "_3DES_") {
			actions = append(actions, "remove 3DES suites")
		}
		if strings.Contains(name, "_RC4_") {
			actions = append(actions, "remove RC4 suites")
		}
		add("legacy", fmt.Sprintf("Accepts weak suite %s (%s)", name, why), sentence(strings.Join(actions, "; ")))
	}

	for _, c := range t.Certificates {
		ref := shortRef(c.Ref)
		switch c.PublicKey.Algorithm {
		case "RSA", "ECDSA", "Ed25519", "DSA":
			add("certificate", fmt.Sprintf("Certificate %s uses %s: a quantum-vulnerable signature algorithm", ref, c.PublicKey.keyLabel()),
				"Plan migration to a post-quantum signature algorithm (e.g. ML-DSA) as the CA and clients support it.")
		}
		v := c.Verification
		if !v.ChainTrusted {
			add("certificate", fmt.Sprintf("Certificate %s does not chain to a trusted root", ref),
				"Confirm it is meant to be trusted privately (internal CA); otherwise replace it with a publicly trusted certificate.")
		}
		if v.HostnameMatch == "mismatch" {
			add("certificate", fmt.Sprintf("Certificate %s does not match the hostname", ref),
				"Replace it with a certificate that matches the hostname.")
		}
		switch v.Validity {
		case "expired":
			add("certificate", fmt.Sprintf("Certificate %s has expired", ref), "Renew the certificate.")
		case "not_yet_valid":
			add("certificate", fmt.Sprintf("Certificate %s is not yet valid", ref), "Check the certificate's start date and the server clock.")
		}
	}
	return out
}

func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:] + "."
}
