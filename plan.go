package main

import (
	"sort"
	"strconv"
	"strings"
)

// Clause 2b, 3 and 4 content built from the assessed report: the indicative
// crypto-agility of each asset, the initiatives that group recurring actions,
// and the items to escalate to the committee (DECISIONS.md, "Expert review,
// group 3"). PROVISIONAL wording.

// AgilityIndicative is an asset's Clause 2b row. It combines scan evidence with
// the mapping file; it is not a full crypto-agility assessment.
type AgilityIndicative struct {
	Level    string   `json:"level"`   // in_place | upgrade | vendor_bound | unknown
	YKnown   string   `json:"y_known"` // per_entry | default | no
	Evidence []string `json:"evidence"`
	Ask      string   `json:"ask"` // what to ask of the vendor or owner
}

const (
	agilityInPlace     = "in_place"
	agilityUpgrade     = "upgrade"
	agilityVendorBound = "vendor_bound"
	agilityUnknown     = "unknown"
)

// Initiative is one recommended action grouped across the assets that need it (Clause 3).
type Initiative struct {
	ID      string   `json:"id"` // I1, I2, ...
	Title   string   `json:"title"`
	Kind    string   `json:"kind"`
	Targets []string `json:"targets"`
	// Assets is the "Assets" cell: system names, or a certificate count.
	Assets  string `json:"assets"`
	Owners  string `json:"owners"`
	Depends string `json:"depends_on"`
}

// CommitteeItem is one challenge or recommendation to escalate (Clause 4).
type CommitteeItem struct {
	Kind  string `json:"kind"` // missing_value | not_assessed | needs_owner_input | mapped_not_scanned | cloud_discovered | out_of_scope
	Ask   string `json:"ask"`
	Why   string `json:"why"`
	Owner string `json:"owner"`
	Due   string `json:"due"`
}

func isVendor(m *MappingEntry) bool {
	return m != nil && strings.TrimSpace(m.ThirdParty) != "" && !isInHouse(m.ThirdParty)
}

func hasFinding(a Asset, area, prefix string) bool {
	for _, f := range a.Findings {
		if f.Area == area && strings.HasPrefix(f.Finding, prefix) {
			return true
		}
	}
	return false
}

// agilityOf rates one assessed asset.
func agilityOf(a Asset) *AgilityIndicative {
	m := a.Mapping
	ag := &AgilityIndicative{Evidence: []string{}}
	switch {
	case a.Mosca.Y == nil:
		ag.YKnown = "no"
	case strings.HasPrefix(a.Mosca.YSource, "per entry"):
		ag.YKnown = "per_entry"
	default:
		ag.YKnown = "default"
	}
	for _, f := range a.Findings {
		if f.Area == "key_exchange" {
			ag.Evidence = append(ag.Evidence, f.Finding)
		}
	}
	ag.Evidence = append(ag.Evidence, a.Agility...)
	noTLS13 := hasFinding(a, "key_exchange", "No TLS 1.3")
	managed := len(a.Agility) > 0
	switch {
	case a.KeyExchange == "hybrid":
		ag.Level = agilityInPlace
		ag.Ask = "Share of clients that negotiate ML-KEM, to decide when classical key exchange can be restricted."
	case isVendor(m):
		ag.Level = agilityVendorBound
		var b strings.Builder
		b.WriteString("A dated plan for ")
		if noTLS13 {
			b.WriteString("TLS 1.3 and ")
		}
		b.WriteString("hybrid key exchange")
		if ag.YKnown == "no" {
			b.WriteString(", with the migration time (Y)")
		}
		if a.Legacy == "yes" {
			b.WriteString("; until then, disabling legacy protocols and weak suites")
		}
		b.WriteString(".")
		ag.Ask = b.String()
	case m == nil || strings.TrimSpace(m.ThirdParty) == "":
		ag.Level = agilityUnknown
		ag.Ask = "State who operates the endpoint (third_party) and the migration time."
	case managed:
		ag.Level = agilityUpgrade
		ag.Ask = "Confirm that clients work with a TLS policy that offers hybrid key exchange."
	default:
		ag.Level = agilityUpgrade
		ag.Ask = "Confirm whether the TLS library supports X25519MLKEM768"
		if ag.YKnown != "per_entry" {
			ag.Ask += ", and the real migration time (Y)"
		}
		ag.Ask += "."
	}
	return ag
}

// initiativeKey sorts a finding into an initiative, or "" for none.
func initiativeKey(f Finding) string {
	switch {
	case f.Area == "third_party":
		return ""
	case f.Area == "key_exchange" && strings.HasPrefix(f.Finding, "Hybrid key exchange available"):
		return "" // no change now: monitoring, not a plan
	case f.Area == "key_exchange":
		return "kex"
	case f.Area == "legacy":
		return "legacy"
	case f.Area == "certificate" && strings.Contains(f.Finding, "quantum-vulnerable signature"):
		return "pqcert"
	case f.Area == "certificate_expiry", f.Area == "certificate" && (strings.HasSuffix(f.Finding, "has expired") || strings.HasSuffix(f.Finding, "is not yet valid")):
		return "renew"
	case f.Area == "certificate" && strings.Contains(f.Finding, "trusted root"):
		return "trust"
	case f.Area == "certificate" && strings.Contains(f.Finding, "hostname"):
		return "host"
	}
	return "other:" + f.Action
}

var initiativeOrder = map[string]int{"kex": 0, "legacy": 1, "pqcert": 2, "renew": 3, "trust": 4, "host": 5}

// joinAnd joins items as "a", "a and b", "a, b and c".
func joinAnd(items []string) string {
	switch n := len(items); n {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:n-1], ", ") + " and " + items[n-1]
	}
}

// uniq keeps the first of each non-empty string, in order.
func uniq(items []string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, s := range items {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// buildInitiatives groups the assets' findings into initiatives, numbers them,
// and marks each finding with its initiative's ID.
func buildInitiatives(assets []Asset) []Initiative {
	type group struct {
		key    string
		assets []int
		certs  []string // certificate refs, for certificate initiatives
		facts  map[string]bool
		action string
	}
	groups := map[string]*group{}
	var keys []string
	for i, a := range assets {
		for _, f := range a.Findings {
			k := initiativeKey(f)
			if k == "" {
				continue
			}
			g := groups[k]
			if g == nil {
				g = &group{key: k, facts: map[string]bool{}, action: f.Action}
				groups[k] = g
				keys = append(keys, k)
			}
			if len(g.assets) == 0 || g.assets[len(g.assets)-1] != i {
				g.assets = append(g.assets, i)
			}
			if f.Area == "certificate" || f.Area == "certificate_expiry" {
				if fs := strings.Fields(f.Finding); len(fs) > 1 {
					g.certs = append(g.certs, fs[1])
				}
			}
			for _, w := range []string{"TLS 1.0", "TLS 1.1", "TLS_RSA_", "_3DES_", "_RC4_", "Cloud record", "No TLS 1.3", "has expired"} {
				if strings.Contains(f.Finding, w) {
					g.facts[w] = true
				}
			}
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		oi, iok := initiativeOrder[keys[i]]
		oj, jok := initiativeOrder[keys[j]]
		switch {
		case iok && jok:
			return oi < oj
		case iok != jok:
			return iok
		}
		return false
	})

	var out []Initiative
	ids := map[string]string{}
	for n, k := range keys {
		g := groups[k]
		in := Initiative{ID: "I" + strconv.Itoa(n+1)}
		ids[k] = in.ID
		var systems, owners, constraints, vendors, issuers []string
		for _, i := range g.assets {
			a := assets[i]
			in.Targets = append(in.Targets, a.Target)
			if m := a.Mapping; m != nil {
				systems = append(systems, m.System)
				owners = append(owners, m.Owner)
				constraints = append(constraints, m.Constraints)
				if isVendor(m) {
					vendors = append(vendors, m.ThirdParty)
				}
			}
			for _, c := range a.Certificates {
				issuers = append(issuers, c.Issuer)
			}
		}
		in.Assets = joinAnd(uniq(systems))
		in.Owners = strings.Join(uniq(owners), "; ")
		certScope := func() string {
			return plural(len(uniq(g.certs)), "certificate", "certificates") + " on " + plural(len(g.assets), "endpoint", "endpoints")
		}
		switch k {
		case "kex":
			in.Title, in.Kind = "Enable hybrid key exchange (X25519MLKEM768)", "Quantum: key exchange"
			var deps []string
			for _, i := range g.assets {
				a := assets[i]
				name := a.Target
				if a.Mapping != nil && a.Mapping.System != "" {
					name = a.Mapping.System
				}
				switch {
				case hasFinding(a, "key_exchange", "No TLS 1.3"):
					d := name + " needs TLS 1.3 first"
					if isVendor(a.Mapping) {
						d += " and a vendor timeline"
					}
					deps = append(deps, d)
				case len(a.Agility) > 0:
					deps = append(deps, name+": a managed TLS policy switch")
				case isVendor(a.Mapping):
					deps = append(deps, name+" needs a vendor timeline")
				default:
					deps = append(deps, name+" may need a TLS library upgrade")
				}
			}
			in.Depends = strings.Join(deps, "; ")
		case "legacy":
			var what []string
			for _, w := range []struct{ fact, label string }{{"TLS 1.0", "TLS 1.0"}, {"TLS 1.1", "TLS 1.1"}, {"TLS_RSA_", "RSA key transport"}, {"_3DES_", "3DES"}, {"_RC4_", "RC4"}} {
				if g.facts[w.fact] {
					what = append(what, w.label)
				}
			}
			if g.facts["Cloud record"] || len(what) == 0 {
				what = append(what, "the legacy settings in cloud TLS policies")
			}
			in.Title, in.Kind = "Retire "+joinAnd(what), "Legacy protocols"
			in.Depends = strings.Join(uniq(append(constraints, vendors...)), "; ")
		case "pqcert":
			in.Title, in.Kind = "Move certificates to a post-quantum signature (ML-DSA)", "Quantum: certificates"
			in.Assets, in.Owners, in.Depends = certScope(), "Issuing CAs: "+strings.Join(uniq(issuers), ", "), "CA and client support for ML-DSA"
		case "renew":
			in.Title, in.Kind = "Renew certificates that expire soon or have expired", "Operational resilience"
			in.Assets, in.Depends = certScope(), "Expiry dates in the Certificates table"
		case "trust":
			in.Title, in.Kind = "Confirm private trust for internal-CA certificates", "Certificates"
			in.Assets, in.Owners = certScope(), "Issuing CAs: "+strings.Join(uniq(issuers), ", ")
		case "host":
			in.Title, in.Kind = "Replace certificates that do not match their hostname", "Certificates"
			in.Assets = certScope()
		default:
			in.Title, in.Kind = strings.TrimSuffix(g.action, "."), "Other"
		}
		if in.Depends == "" {
			in.Depends = "—"
		}
		out = append(out, in)
	}
	for i := range assets {
		for j := range assets[i].Findings {
			assets[i].Findings[j].Initiative = ids[initiativeKey(assets[i].Findings[j])]
		}
	}
	return out
}

// legacyShort lists an asset's legacy findings briefly: "TLS 1.0, TLS 1.1 and RSA key transport".
func legacyShort(a Asset) string {
	var what []string
	for _, f := range a.Findings {
		switch {
		case f.Area != "legacy":
		case strings.HasPrefix(f.Finding, "Accepts TLS "):
			what = append(what, strings.TrimPrefix(f.Finding, "Accepts "))
		case strings.Contains(f.Finding, "TLS_RSA_"):
			what = append(what, "RSA key transport")
		case strings.Contains(f.Finding, "_3DES_"):
			what = append(what, "3DES")
		case strings.Contains(f.Finding, "_RC4_"):
			what = append(what, "RC4")
		}
	}
	return joinAnd(uniq(what))
}

var statusWords = map[string]string{statusAtRisk: "at risk", statusNotAtRisk: "not at risk", statusMitigated: "mitigated for PQ-capable clients", statusUnknown: "of unknown priority"}

// buildCommitteeItems turns the scan's open questions into items to escalate.
func buildCommitteeItems(r RiskReport) []CommitteeItem {
	due := "Before " + strings.ToLower(clauses[1].Due[:1]) + clauses[1].Due[1:] // Clause 2's deadline
	var out []CommitteeItem
	names := func(as []Asset) []string {
		var s []string
		for _, a := range as {
			if a.Mapping != nil && a.Mapping.System != "" {
				s = append(s, a.Mapping.System)
			} else {
				s = append(s, a.Target)
			}
		}
		return s
	}
	owners := func(as []Asset) string {
		var s []string
		for _, a := range as {
			if a.Mapping != nil {
				s = append(s, a.Mapping.Owner)
			}
		}
		if s = uniq(s); len(s) == 0 {
			return "—"
		}
		return strings.Join(s, "; ")
	}

	// Missing Y, one item per vendor, then one for owners.
	byVendor := map[string][]Asset{}
	var vendors []string
	var ownerAsk []Asset
	for _, a := range r.Assets {
		switch {
		case a.Mosca.Y != nil:
		case isVendor(a.Mapping):
			v := strings.TrimSpace(a.Mapping.ThirdParty)
			if byVendor[v] == nil {
				vendors = append(vendors, v)
			}
			byVendor[v] = append(byVendor[v], a)
		default:
			ownerAsk = append(ownerAsk, a)
		}
	}
	why := func(as []Asset) string {
		var parts []string
		for _, a := range as {
			p := []string{}
			if c := a.Mapping.DataClassification; c != "" {
				p = append(p, c+" data")
			}
			st := statusWords[a.Mosca.Status]
			if a.Mosca.Margin != nil {
				m := signedYears(a.Mosca.Margin)
				if a.Mosca.MarginIsLowerBound {
					m = "≥ " + m
				}
				st += " (margin " + m + ")"
			}
			p = append(p, st)
			if l := legacyShort(a); l != "" {
				p = append(p, "accepts "+l)
			}
			if c := strings.TrimSpace(a.Mapping.Constraints); c != "" {
				p = append(p, strings.ToLower(c[:1])+c[1:])
			}
			s := strings.Join(p, ", ")
			if len(as) > 1 {
				s = names([]Asset{a})[0] + ": " + s
			}
			parts = append(parts, strings.ToUpper(s[:1])+s[1:])
		}
		return strings.Join(parts, ". ") + "."
	}
	for _, v := range vendors {
		as := byVendor[v]
		out = append(out, CommitteeItem{Kind: "missing_value", Ask: "Ask " + v + " for a dated migration plan for " + joinAnd(names(as)) + ".",
			Why: why(as), Owner: owners(as), Due: due})
	}
	if len(ownerAsk) > 0 {
		out = append(out, CommitteeItem{Kind: "missing_value", Ask: "Get the migration time (Y) for " + joinAnd(names(ownerAsk)) + " from " + map[bool]string{true: "its owner", false: "their owners"}[len(ownerAsk) == 1] + ".",
			Why: why(ownerAsk), Owner: owners(ownerAsk), Due: due})
	}

	c := r.Completeness
	if n := len(r.NotAssessed); n > 0 {
		unreachable := true
		for _, a := range r.NotAssessed {
			unreachable = unreachable && strings.HasPrefix(a.Problem, "unreachable")
		}
		ask := "Resolve the scan problems of " + joinAnd(names(r.NotAssessed)) + ", then rescan."
		if unreachable {
			ask = "Restore reachability of " + joinAnd(names(r.NotAssessed)) + ", then rescan."
		}
		out = append(out, CommitteeItem{Kind: "not_assessed", Ask: ask,
			Why: map[bool]string{true: "It is", false: "They are"}[n == 1] + " mapped, but nothing about " + map[bool]string{true: "its", false: "their"}[n == 1] +
				" TLS is known; Clause 2 completeness stays at " + strconv.Itoa(c.Assessed) + " of " + strconv.Itoa(c.Known()) + " until " + map[bool]string{true: "it is", false: "they are"}[n == 1] + " assessed.",
			Owner: owners(r.NotAssessed), Due: due})
	}
	if n := len(r.NeedsOwnerInput); n > 0 {
		out = append(out, CommitteeItem{Kind: "needs_owner_input", Ask: "Name an owner, system and data classification for " + plural(n, "scanned target", "scanned targets") + " not in the mapping file.",
			Why: "Without them there is no priority; they are not counted as assessed.", Owner: "—", Due: due})
	}
	if n := len(r.MappedNotScanned); n > 0 {
		out = append(out, CommitteeItem{Kind: "mapped_not_scanned", Ask: "Scan " + plural(n, "mapped target", "mapped targets") + " that " + map[bool]string{true: "was", false: "were"}[n == 1] + " not scanned.",
			Why: "Mapped targets left out of the scan keep Clause 2 completeness down.", Owner: "—", Due: due})
	}
	if n := len(r.CloudDiscovered); n > 0 {
		out = append(out, CommitteeItem{Kind: "cloud_discovered", Ask: "Review " + plural(n, "cloud endpoint", "cloud endpoints") + " found in the cloud records but not in the target list.",
			Why: "Endpoints in the account but not in the inventory; Hasr never scans them automatically.", Owner: "—", Due: due})
	}
	out = append(out, CommitteeItem{Kind: "out_of_scope", Ask: "Approve the scope and an owner for cryptographic assets other than TLS endpoints.",
		Why:   "SSH, VPN, HSMs and key stores, application code and databases are outside this scan; Clause 2 covers all cryptographic assets.",
		Owner: "Information security committee", Due: "Decision"})
	return out
}
