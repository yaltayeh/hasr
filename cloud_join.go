package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yaltayeh/hasr/internal/cloud"
)

// cloudFile is one --cloud input: a provider-neutral inventory and its path.
type cloudFile struct {
	Path string
	Inv  cloud.Inventory
}

// CloudInput describes one cloud inventory the report read.
type CloudInput struct {
	File        string        `json:"file"`
	Provider    string        `json:"provider"`
	GeneratedAt time.Time     `json:"generated_at"`
	CollectedAt time.Time     `json:"collected_at"` // when the collector finished
	Scopes      []cloud.Scope `json:"scopes"`
}

// CloudMatch is a cloud endpoint matched to a scanned target.
type CloudMatch struct {
	Provider   string     `json:"provider"`
	Scope      string     `json:"scope"`
	ResourceID string     `json:"resource_id"`
	Name       string     `json:"name"`
	Port       int        `json:"port"`
	Protocol   string     `json:"protocol"`
	Match      string     `json:"match"` // hostname | cname
	TLS        *cloud.TLS `json:"tls"`
	Notes      []string   `json:"notes,omitempty"`
}

// Disagreement is a field where the scan and a matched cloud record differ.
// The worse of the two counts (DECISIONS.md, "Joining the scan and the cloud data").
type Disagreement struct {
	Target   string `json:"target"`
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Field    string `json:"field"`
	Scan     string `json:"scan"`
	Cloud    string `json:"cloud"`
	Counted  string `json:"counted"` // the value the report uses
}

const disagreementCauses = "something in front of the endpoint (a CDN or proxy), a wrong match, or a change between the scan and the cloud read"

// cloudInputs summarises the inventories for Inputs.
func cloudInputs(files []cloudFile) []CloudInput {
	out := []CloudInput{}
	for _, f := range files {
		out = append(out, CloudInput{
			File: f.Path, Provider: f.Inv.Provider, GeneratedAt: f.Inv.GeneratedAt,
			CollectedAt: f.Inv.Collection.FinishedAt, Scopes: f.Inv.Scopes,
		})
	}
	return out
}

// cloudLimits turns failed or partial scopes and each provider's not-read list
// into stated limits under Clause 2.
func cloudLimits(files []cloudFile) []Limit {
	out := []Limit{}
	for _, f := range files {
		p := f.Inv.Provider
		for _, s := range f.Inv.Scopes {
			if s.Status != cloud.ScopeRead {
				detail := "scope " + s.Scope + " " + s.Status
				if len(s.Errors) > 0 {
					detail += ": " + strings.Join(s.Errors, "; ")
				}
				out = append(out, Limit{ID: p + "_scope_" + s.Scope, Detail: detail})
			}
		}
		for _, l := range f.Inv.NotRead {
			out = append(out, Limit{ID: l.ID, Detail: l.Detail})
		}
	}
	return out
}

type endpointMatch struct {
	e   cloud.Endpoint
	how string
}

// matchCloud finds the cloud endpoints for a target: same port, and the
// target's host (or the end of its CNAME chain) is one of the endpoint's hostnames.
func matchCloud(target, canonical string, files []cloudFile) []endpointMatch {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	host = normalizeHost(host)
	var out []endpointMatch
	for _, f := range files {
		for _, e := range f.Inv.Endpoints {
			if e.Port != port {
				continue
			}
			for _, h := range e.Hostnames {
				h = normalizeHost(h)
				switch {
				case h == host:
					out = append(out, endpointMatch{e, "hostname"})
				case canonical != "" && h == canonical:
					out = append(out, endpointMatch{e, "cname"})
				default:
					continue
				}
				break
			}
		}
	}
	return out
}

var (
	kexRank    = map[string]int{"hybrid": 0, "unknown": 1, "classical": 2}
	legacyRank = map[string]int{"no": 0, "unknown": 1, "yes": 2}
)

// applyCloud returns the target with the worst of the scan and every matched
// record, the matches, and the disagreements.
func applyCloud(t Target, ms []endpointMatch) (Target, []CloudMatch, []Disagreement) {
	if len(ms) == 0 {
		return t, nil, nil
	}
	s := t.Summary
	s.KeyExchangeReasons = append([]string{}, s.KeyExchangeReasons...)
	s.LegacyReasons = append([]string{}, s.LegacyReasons...)
	var matches []CloudMatch
	var dis []Disagreement
	scanRefs := map[string]bool{}
	for _, c := range t.Certificates {
		scanRefs[c.Ref] = true
	}

	for _, m := range ms {
		e := m.e
		matches = append(matches, CloudMatch{
			Provider: e.Provider, Scope: e.Scope, ResourceID: e.ResourceID, Name: e.Name,
			Port: e.Port, Protocol: e.Protocol, Match: m.how, TLS: e.TLS, Notes: e.Notes,
		})
		tl := e.TLS
		if tl == nil {
			continue
		}
		if tl.Policy.Managed {
			t.managedTLS = true
		}
		label := e.Provider + " " + e.Name
		d := func(field, scan, cl, counted string) {
			dis = append(dis, Disagreement{Target: t.Target, Provider: e.Provider, Name: e.Name, Field: field, Scan: scan, Cloud: cl, Counted: counted})
		}

		// Key exchange: worst counts.
		scanKex := t.Summary.KeyExchange
		if scanKex != "unknown" && tl.KeyExchange != "unknown" && scanKex != tl.KeyExchange {
			d("key_exchange", scanKex, tl.KeyExchange+" (policy "+tl.Policy.Name+")", worst(kexRank, scanKex, tl.KeyExchange))
		}
		if kexRank[tl.KeyExchange] > kexRank[s.KeyExchange] {
			s.KeyExchange = tl.KeyExchange
			for _, r := range tl.KeyExchangeReasons {
				s.KeyExchangeReasons = append(s.KeyExchangeReasons, "cloud ("+label+"): "+r)
			}
		}

		// Legacy: worst counts; cloud reasons are always listed.
		scanLegacy := t.Summary.Legacy
		if scanLegacy != "unknown" && tl.Legacy != "unknown" && scanLegacy != tl.Legacy {
			d("legacy", scanLegacy, tl.Legacy, worst(legacyRank, scanLegacy, tl.Legacy))
		}
		if legacyRank[tl.Legacy] > legacyRank[s.Legacy] {
			s.Legacy = tl.Legacy
		}
		if tl.Legacy == "yes" {
			for _, r := range tl.LegacyReasons {
				s.LegacyReasons = append(s.LegacyReasons, "cloud ("+label+"): "+r)
			}
		}

		// Versions: compared only when both sides are known.
		if tl.Policy.ContentsKnown && t.Summary.Complete && len(t.Summary.VersionsAccepted) > 0 {
			if a, b := shortVersions(t.Summary.VersionsAccepted), shortVersions(tl.Versions); a != b {
				d("tls_versions", a, b, "both listed; legacy and key exchange take the worse")
			}
		}

		// Certificate cross-check.
		var cloudRefs []string
		overlap := false
		for _, c := range tl.Certificates {
			if c.Ref != "" {
				cloudRefs = append(cloudRefs, shortRef(c.Ref))
				overlap = overlap || scanRefs[c.Ref]
			}
		}
		if len(cloudRefs) > 0 && len(scanRefs) > 0 && !overlap {
			var sr []string
			for r := range scanRefs {
				sr = append(sr, shortRef(r))
			}
			sort.Strings(sr)
			d("certificate", strings.Join(sr, ", "), strings.Join(cloudRefs, ", "), "the scanned certificate is reported")
		}
	}
	t.Summary = s
	return t, matches, dis
}

func worst(rank map[string]int, a, b string) string {
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// applyRecommendation replaces the action of the scan's key-exchange finding
// with a matched managed-policy record's recommendation, and notes in the
// finding what the switch changes. The scan's evidence stays. It reports
// whether a recommendation was applied.
func applyRecommendation(fs []Finding, ms []CloudMatch) bool {
	for _, m := range ms {
		tl := m.TLS
		if tl == nil || !tl.Policy.Managed || tl.Recommendation == nil {
			continue
		}
		for i := range fs {
			if fs[i].Area != "key_exchange" {
				continue
			}
			rec := tl.Recommendation
			note := fmt.Sprintf("Cloud record: %s %s uses the managed TLS policy %s", m.Provider, m.Name, tl.Policy.Name)
			if len(rec.Effects) > 0 {
				note += "; this single switch " + strings.Join(rec.Effects, ", ")
			}
			fs[i].Finding += ". " + note + "."
			fs[i].Action = rec.Action
			if len(rec.Links) > 0 {
				fs[i].Action += " Source: " + strings.Join(rec.Links, " ")
			}
			return true
		}
	}
	return false
}

// cloudFindings adds findings from the matched records, with generic actions:
// the provider's own rule is in the record's basis. When the scan's
// key-exchange finding already carries the recommendation, the record's own
// key-exchange finding is not repeated.
func cloudFindings(ms []CloudMatch, recommended bool) []Finding {
	var out []Finding
	for _, m := range ms {
		tl := m.TLS
		if tl == nil {
			continue
		}
		where := fmt.Sprintf("%s %s, port %d, policy %s", m.Provider, m.Name, m.Port, tl.Policy.Name)
		if tl.KeyExchange == "classical" && !recommended {
			action := "Switch the endpoint to a TLS policy with hybrid key exchange."
			switch {
			case tl.Recommendation != nil:
				action = tl.Recommendation.Action
				if len(tl.Recommendation.Links) > 0 {
					action += " Source: " + strings.Join(tl.Recommendation.Links, " ")
				}
			case tl.Policy.Managed:
				action = "Switch the endpoint's managed TLS policy to one with hybrid key exchange; this is a setting, changeable in place."
			}
			out = append(out, Finding{Area: "key_exchange", Finding: "Cloud record (" + where + "): classical key exchange only", Action: action})
		}
		for _, r := range tl.LegacyReasons {
			if tl.Legacy != "yes" {
				break
			}
			out = append(out, Finding{Area: "legacy", Finding: "Cloud record (" + where + "): " + r,
				Action: "Switch to a TLS policy without legacy protocol versions or weak suites."})
		}
	}
	return out
}

// agilityEvidence is the Clause 2b evidence from cloud records.
func agilityEvidence(ms []CloudMatch) []string {
	var out []string
	for _, m := range ms {
		if m.TLS != nil && m.TLS.Policy.Managed {
			out = append(out, fmt.Sprintf("TLS policy is a managed setting on %s %s (%s): changeable in place", m.Provider, m.Name, m.TLS.Policy.Name))
		}
	}
	return out
}

// fillFromLabels fills empty owner, system and service fields from the matched
// records' tags (never data_classification). The mapping file wins.
func fillFromLabels(m MappingEntry, ms []endpointMatch) (MappingEntry, map[string]string) {
	sources := map[string]string{}
	fields := []struct {
		name string
		val  *string
	}{{"owner", &m.Owner}, {"system", &m.System}, {"service", &m.Service}}
	for _, f := range fields {
		if strings.TrimSpace(*f.val) != "" {
			continue
		}
		for _, em := range ms {
			if k, v, ok := labelFor(em.e.Labels, f.name); ok {
				*f.val = v
				sources[f.name] = fmt.Sprintf("tag %q on %s %s", k, em.e.Provider, em.e.Name)
				break
			}
		}
	}
	if len(sources) == 0 {
		return m, nil
	}
	return m, sources
}

func labelFor(labels map[string]string, name string) (string, string, bool) {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, name) && strings.TrimSpace(labels[k]) != "" {
			return k, strings.TrimSpace(labels[k]), true
		}
	}
	return "", "", false
}

// discovered returns the endpoints no scanned or mapped target matched.
func discovered(files []cloudFile, used map[string]bool, mapping []MappingEntry) []cloud.Endpoint {
	out := []cloud.Endpoint{}
	for _, f := range files {
		for _, e := range f.Inv.Endpoints {
			if used[e.ResourceID] || mappedHostPort(e, mapping) {
				continue
			}
			out = append(out, e)
		}
	}
	return out
}

func mappedHostPort(e cloud.Endpoint, mapping []MappingEntry) bool {
	for _, m := range mapping {
		if len(matchCloud(m.Target, "", []cloudFile{{Inv: cloud.Inventory{Endpoints: []cloud.Endpoint{e}}}})) > 0 {
			return true
		}
	}
	return false
}
