package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yaltayeh/hasr/internal/cloud"
)

const reportSchemaVersion = "0.3" // 0.2 added the cloud fields; 0.3 the margin lower bound, flag, agility, initiatives and committee items

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

	// Cloud (only when --cloud files were given).
	// Disagreements between the scan and matched cloud records; the worse counts.
	Disagreements []Disagreement `json:"disagreements"`
	// CloudDiscovered are cloud endpoints that no scanned or mapped target matched.
	CloudDiscovered []cloud.Endpoint `json:"cloud_discovered"`
	// CloudLimits are the cloud collectors' stated limits, including failed scopes.
	CloudLimits []Limit `json:"cloud_limits"`

	// Initiatives group recurring actions across assets (Clause 3).
	Initiatives []Initiative `json:"initiatives"`
	// CommitteeItems are challenges and recommendations to escalate (Clause 4).
	CommitteeItems []CommitteeItem `json:"committee_items"`
}

type Inputs struct {
	ScanFile          string       `json:"scan_file"`
	ScanGeneratedAt   time.Time    `json:"scan_generated_at"`
	ScanSchemaVersion string       `json:"scan_schema_version"`
	ScanTool          Tool         `json:"scan_tool"`
	MappingFile       string       `json:"mapping_file"`
	PolicyFile        string       `json:"policy_file"` // empty = built-in defaults
	Cloud             []CloudInput `json:"cloud"`
}

type Completeness struct {
	Mapped           int `json:"mapped"`   // rows in the mapping file
	Assessed         int `json:"assessed"` // mapped, scanned and complete
	MappedNotScanned int `json:"mapped_not_scanned"`
	NotAssessed      int `json:"not_assessed"`
	NeedsOwnerInput  int `json:"needs_owner_input"`
	Scanned          int `json:"scanned"`
	// CloudDiscovered count against completeness: known targets = mapped + discovered.
	CloudDiscovered int `json:"cloud_discovered"`
}

// Known is the denominator of the completeness figure.
func (c Completeness) Known() int { return c.Mapped + c.CloudDiscovered }

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
	// Cloud records matched to this target, and what they add.
	Cloud []CloudMatch `json:"cloud,omitempty"`
	// FieldSources says where a mapping field came from when it was not the mapping file.
	FieldSources map[string]string `json:"field_sources,omitempty"`
	// Agility is Clause 2b evidence from cloud records.
	Agility []string `json:"agility,omitempty"`
	// AgilityIndicative is the asset's Clause 2b row (assessed assets only).
	AgilityIndicative *AgilityIndicative `json:"agility_indicative,omitempty"`
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
	Margin      *float64 `json:"margin"` // X + Y - Z; X - Z when MarginIsLowerBound
	// MarginIsLowerBound: Y is unknown, so Margin is X - Z, a lower bound (Y >= 0).
	MarginIsLowerBound bool `json:"margin_is_lower_bound"`
	// Flag names the value to ask for when Y is unknown, e.g. "Y unknown: ask vendor".
	Flag string `json:"flag,omitempty"`
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
	Area    string `json:"area"` // third_party | key_exchange | legacy | certificate | certificate_expiry
	Finding string `json:"finding"`
	Action  string `json:"action"`
	// Initiative is the Clause 3 initiative this action belongs to (I1, I2, ...), if any.
	Initiative string `json:"initiative,omitempty"`
}

// certExpiryDays is how close to expiry a certificate gets a certificate_expiry finding.
const certExpiryDays = 90

// Limit is something the scanner did not test.
type Limit struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

func buildReport(scan Report, inputs Inputs, mapping []MappingEntry, pol Policy, now time.Time, clouds ...cloudFile) RiskReport {
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
		Disagreements:    []Disagreement{},
		CloudDiscovered:  []cloud.Endpoint{},
		CloudLimits:      cloudLimits(clouds),
	}
	r.Inputs.Cloud = cloudInputs(clouds)
	usedCloud := map[string]bool{}
	byTarget := map[string]*MappingEntry{}
	for i := range mapping {
		byTarget[mapping[i].Target] = &mapping[i]
	}
	scanned := map[string]bool{}
	seenLimit := map[string]bool{}

	for _, t := range scan.Targets {
		scanned[t.Target] = true
		m := byTarget[t.Target]
		ems := matchCloud(t.Target, t.CanonicalName, clouds)
		var sources map[string]string
		if m != nil && len(ems) > 0 {
			filled, src := fillFromLabels(*m, ems)
			m, sources = &filled, src
		}
		t, matches, dis := applyCloud(t, ems)
		r.Disagreements = append(r.Disagreements, dis...)
		for _, em := range ems {
			usedCloud[em.e.ResourceID] = true
		}
		a := assessTarget(t, m, pol)
		a.Cloud, a.FieldSources, a.Agility = matches, sources, agilityEvidence(matches)
		recommended := applyRecommendation(a.Findings, matches)
		a.Findings = append(a.Findings, cloudFindings(matches, recommended)...)
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
	sortByPriority(r.Assets, pol)
	for i := range r.Assets {
		r.Assets[i].AgilityIndicative = agilityOf(r.Assets[i])
	}
	r.Initiatives = buildInitiatives(r.Assets)
	r.CloudDiscovered = discovered(clouds, usedCloud, mapping)

	r.Completeness = Completeness{
		Mapped:           len(mapping),
		Assessed:         len(r.Assets),
		MappedNotScanned: len(r.MappedNotScanned),
		NotAssessed:      len(r.NotAssessed),
		NeedsOwnerInput:  len(r.NeedsOwnerInput),
		Scanned:          len(scan.Targets),
		CloudDiscovered:  len(r.CloudDiscovered),
	}
	r.CommitteeItems = buildCommitteeItems(r)
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
	case len(s.VersionsAccepted) == 0 && noTCP(t):
		// Silence or refusal at the TCP level: nothing about TLS is known.
		a.Problem = "unreachable: no TCP connection (" + tcpReason(t) + "); nothing about its TLS is known"
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
		// A missing Y is the first thing to act on: it is asked of someone.
		switch a.Mosca.Flag {
		case "Y unknown: ask vendor":
			a.Findings = append([]Finding{{Area: "third_party", Finding: "Y unknown: no migration timeline from " + strings.TrimSpace(m.ThirdParty),
				Action: "Ask the vendor for a dated migration plan; set migration_years for this entry."}}, a.Findings...)
		case "Y unknown: ask owner":
			a.Findings = append([]Finding{{Area: "third_party", Finding: "Y unknown: migration time not stated",
				Action: "Ask the owner for the migration time; set migration_years for this entry (and third_party, if empty)."}}, a.Findings...)
		}
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
	switch {
	case mo.X != nil && mo.Y != nil && mo.Z != nil:
		margin := round2(*mo.X + *mo.Y - *mo.Z)
		mo.Margin = &margin
	case mo.X != nil && mo.Y == nil && mo.Z != nil:
		// Y >= 0, so X - Z is a lower bound on the margin. Above 0, the asset is
		// at risk whatever Y turns out to be (DECISIONS.md, "Mosca lower bound").
		if lb := round2(*mo.X - *mo.Z); lb > 0 {
			mo.Margin, mo.MarginIsLowerBound = &lb, true
			mo.Notes = append(mo.Notes, "margin is a lower bound: X − Z = "+num(lb)+" > 0, and Y ≥ 0")
		} else {
			mo.Notes = append(mo.Notes, "X − Z = "+num(lb)+" ≤ 0: the outcome depends on Y")
		}
	}
	if mo.Y == nil {
		switch {
		case strings.TrimSpace(m.ThirdParty) != "" && !isInHouse(m.ThirdParty):
			mo.Flag = "Y unknown: ask vendor"
		default:
			mo.Flag = "Y unknown: ask owner"
		}
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

// noTCP reports whether every probe that ran ended without a TCP connection.
func noTCP(t Target) bool {
	ran := 0
	for _, p := range t.Probes {
		if p.Result == resultNotTested {
			continue
		}
		ran++
		if p.Result != resultError || p.Stage != stageTCP {
			return false
		}
	}
	return ran > 0
}

// tcpReason says whether the TCP attempts timed out (silence) or failed otherwise.
func tcpReason(t Target) string {
	for _, p := range t.Probes {
		// Detail is the error text, then "; " and the probe's note, if any.
		if d := strings.SplitN(p.Detail, "; ", 2)[0]; p.Stage == stageTCP && !strings.Contains(d, "(timeout)") {
			return "connection attempts failed: " + strings.TrimPrefix(d, "no TCP connection: ")
		}
	}
	return "every connection attempt timed out: no answer at all"
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
	case t.managedTLS:
		// A managed TLS policy is switched by a setting, whatever the protocol versions.
		return catManagedTLS
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

// sortByPriority: at risk, then unknown, then not at risk, then mitigated.
// Within a status: sensitivity (the policy's first level first; no or an
// unlisted classification last), then legacy, then a third party, then the
// largest margin (DECISIONS.md, "Order within a status").
func sortByPriority(as []Asset, pol Policy) {
	rank := map[string]int{statusAtRisk: 0, statusUnknown: 1, statusNotAtRisk: 2, statusMitigated: 3}
	sensitivity := func(a Asset) int {
		if a.Mapping != nil {
			for i, l := range pol.ClassificationLevels {
				if l.Label == a.Mapping.DataClassification {
					return i
				}
			}
		}
		return len(pol.ClassificationLevels)
	}
	third := func(a Asset) bool {
		return a.Mapping != nil && strings.TrimSpace(a.Mapping.ThirdParty) != "" && !isInHouse(a.Mapping.ThirdParty)
	}
	margin := func(a Asset) float64 {
		if a.Mosca.Margin == nil {
			return 0
		}
		return *a.Mosca.Margin
	}
	sort.SliceStable(as, func(i, j int) bool {
		a, b := as[i], as[j]
		if ri, rj := rank[a.Mosca.Status], rank[b.Mosca.Status]; ri != rj {
			return ri < rj
		}
		if si, sj := sensitivity(a), sensitivity(b); si != sj {
			return si < sj
		}
		if li, lj := a.Legacy == "yes", b.Legacy == "yes"; li != lj {
			return li
		}
		if ti, tj := third(a), third(b); ti != tj {
			return ti
		}
		if mi, mj := margin(a), margin(b); mi != mj {
			return mi > mj
		}
		return a.Target < b.Target
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
		default:
			if n, ok := daysLeft(t.ScannedAt, c.NotAfter.UTC().Format("2006-01-02")); ok && n >= 0 && n <= certExpiryDays {
				add("certificate_expiry", fmt.Sprintf("Certificate %s expires %s, %s after the scan", ref, c.NotAfter.UTC().Format("2006-01-02"), plural(n, "day", "days")),
					"Renew before expiry. Operational resilience, not a quantum finding.")
			}
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
