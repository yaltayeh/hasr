package main

import (
	"crypto/tls"
	"sort"
	"strings"
)

// Summary holds the two independent classifications (DECISIONS.md,
// "Classification: two independent fields").
type Summary struct {
	KeyExchange          string   `json:"key_exchange"` // hybrid | classical | unknown
	KeyExchangeReasons   []string `json:"key_exchange_reasons"`
	Legacy               string   `json:"legacy"` // yes | no | unknown
	LegacyReasons        []string `json:"legacy_reasons"`
	VersionsAccepted     []string `json:"versions_accepted"`
	HybridGroupsAccepted []Named  `json:"hybrid_groups_accepted"`
	// Complete is false when any probe ended in error. An error never clears a rule.
	Complete           bool     `json:"complete"`
	InconclusiveProbes []string `json:"inconclusive_probes,omitempty"`
}

const noTLS13Reason = "no TLS 1.3: hybrid key exchange needs a protocol upgrade first"

func summarize(probes []Probe) Summary {
	s := Summary{
		KeyExchangeReasons:   []string{},
		LegacyReasons:        []string{},
		VersionsAccepted:     []string{},
		HybridGroupsAccepted: []Named{},
	}
	result := map[string]string{}
	versions := map[uint16]bool{}
	seenHybrid := map[uint16]bool{}
	seenWeak := map[string]bool{}
	var weakReasons []string
	accepted := 0

	for _, p := range probes {
		result[p.ID] = p.Result
		switch p.Result {
		case resultError:
			s.InconclusiveProbes = append(s.InconclusiveProbes, p.ID)
		case resultAccepted:
			accepted++
			n := p.Negotiated
			versions[n.version] = true
			if g := n.Group; g != nil && hybridGroups[g.Codepoint] && !seenHybrid[g.Codepoint] {
				seenHybrid[g.Codepoint] = true
				s.HybridGroupsAccepted = append(s.HybridGroupsAccepted, *g)
			}
			if why := weakSuiteReason(n.CipherSuite.Name); why != "" && !seenWeak[n.CipherSuite.Name] {
				seenWeak[n.CipherSuite.Name] = true
				weakReasons = append(weakReasons, "weak suite accepted: "+n.CipherSuite.Name+" ("+why+")")
			}
		}
	}
	s.Complete = len(s.InconclusiveProbes) == 0
	conclusive := func(ids ...string) bool {
		for _, id := range ids {
			if r := result[id]; r != resultAccepted && r != resultRejected && r != resultClosed {
				return false
			}
		}
		return true
	}

	var vs []uint16
	for v := range versions {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
	for _, v := range vs {
		s.VersionsAccepted = append(s.VersionsAccepted, tls.VersionName(v))
	}

	// Key exchange: the harvest-now-decrypt-later axis.
	switch {
	case len(s.HybridGroupsAccepted) > 0:
		s.KeyExchange = "hybrid"
		for _, g := range s.HybridGroupsAccepted {
			s.KeyExchangeReasons = append(s.KeyExchangeReasons, "hybrid group negotiated: "+g.Name)
		}
	case accepted == 0:
		s.KeyExchange = "unknown"
		s.KeyExchangeReasons = append(s.KeyExchangeReasons, "no probe accepted")
	case !conclusive("default", "hybrid_only"):
		// Only these two offer a hybrid group; without both answers "classical" is not proven.
		s.KeyExchange = "unknown"
		s.KeyExchangeReasons = append(s.KeyExchangeReasons, "inconclusive: a probe that offers a hybrid group ended in error")
	default:
		s.KeyExchange = "classical"
		s.KeyExchangeReasons = append(s.KeyExchangeReasons, "no hybrid group negotiated")
	}
	// Every probe that offers TLS 1.3 must have answered before "no TLS 1.3" is claimed.
	if accepted > 0 && !versions[tls.VersionTLS13] && conclusive("default", "hybrid_only", "classical_only") {
		s.KeyExchangeReasons = append(s.KeyExchangeReasons, noTLS13Reason)
	}

	// Legacy: things that can be switched off by configuration.
	if versions[tls.VersionTLS10] {
		s.LegacyReasons = append(s.LegacyReasons, "accepts TLS 1.0")
	}
	if versions[tls.VersionTLS11] {
		s.LegacyReasons = append(s.LegacyReasons, "accepts TLS 1.1")
	}
	s.LegacyReasons = append(s.LegacyReasons, weakReasons...)
	switch {
	case len(s.LegacyReasons) > 0:
		s.Legacy = "yes"
	case conclusive("tls10_only", "tls11_only", "tls12_weak"):
		s.Legacy = "no"
	default:
		// No finding, but a legacy probe gave no answer: the rule is not cleared.
		s.Legacy = "unknown"
	}
	return s
}

// shortVersions renders ["TLS 1.2", "TLS 1.3"] as "1.2 1.3".
func shortVersions(vs []string) string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = strings.TrimPrefix(v, "TLS ")
	}
	return strings.Join(out, " ")
}
