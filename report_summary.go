package main

import (
	"strconv"
	"strings"
)

// The one-page committee summary: the report's default print (DECISIONS.md,
// "Expert review, group 4"). Plain language; no "Not tested" and no "+N more".

type summaryView struct {
	ScanDay  string
	Headline string
	Clauses  []coverageRow
	Cards    []summaryCard
	Rows     []summaryRow
	// More says how many assessed assets the table leaves out, in a sentence.
	More     string
	ZYear    string
	CertNote string
	Items    []CommitteeItem
}

type summaryCard struct {
	N, Label, Note, Class string
}

type summaryRow struct {
	System, Service, Sensitivity string
	Status, StatusNote, Class    string
	Exposure, ExposureNote       string
	Third, Constraint, Do        string
}

// summaryRows is how many assets the one-page table shows, in priority order.
const summaryRows = 6

func buildSummary(r RiskReport, v htmlView) summaryView {
	c := r.Completeness
	sv := summaryView{ScanDay: r.Inputs.ScanGeneratedAt.UTC().Format("2006-01-02"), Clauses: append([]coverageRow(nil), v.Coverage...), Items: r.CommitteeItems, ZYear: "2030"}
	if len(r.Policy.Z.Date) >= 4 {
		sv.ZYear = r.Policy.Z.Date[:4]
	}

	// Headline.
	var h []string
	switch atRisk := v.Counts[statusAtRisk]; {
	case c.Assessed == 0:
		h = append(h, "No TLS endpoint was fully assessed.")
	default:
		verb := map[bool]string{true: " is", false: " are"}[atRisk == 1]
		if atRisk == 0 {
			h = append(h, "None of the "+plural(c.Assessed, "assessed TLS endpoint", "assessed TLS endpoints")+" is at risk from quantum computing.")
		} else {
			h = append(h, strconv.Itoa(atRisk)+" of "+plural(c.Assessed, "assessed TLS endpoint", "assessed TLS endpoints")+verb+" at risk from quantum computing.")
		}
	}
	if n := c.Known() - c.Assessed; n > 0 && c.Assessed > 0 {
		h = append(h, strconv.Itoa(n)+" more could not be assessed.")
	}
	for _, cl := range v.Coverage {
		if cl.N == 2 && cl.Left != "" {
			if strings.HasSuffix(cl.Left, "overdue") {
				h = append(h, "Clause 2 (inventory) is "+cl.Left+".")
			} else {
				h = append(h, "Clause 2 (inventory) is due in "+strings.TrimSuffix(cl.Left, " left")+".")
			}
		}
	}
	sv.Headline = strings.Join(h, " ")

	// Clause tiles: short statuses.
	for i := range sv.Clauses {
		cl := &sv.Clauses[i]
		cl.Left = strings.TrimSuffix(cl.Left, " left")
		switch cl.N {
		case 1:
			cl.SumStatus = cl.Status
		case 2:
			cl.SumStatus = "Partial: TLS only, " + strconv.Itoa(c.Assessed) + " of " + strconv.Itoa(c.Known())
		case 3:
			cl.SumStatus = plural(len(r.Initiatives), "initiative", "initiatives") + " proposed"
			cl.SumWhen = "No date in the circular"
		case 4:
			cl.SumStatus = plural(len(r.CommitteeItems), "item", "items") + " to escalate"
			cl.SumWhen = "No trend yet: comparison between scans is not built"
		}
	}

	// Cards: at risk, then the other statuses that occur, not assessed, completeness.
	vendorBound := 0
	for _, a := range r.Assets {
		if a.Mosca.Status == statusAtRisk && isVendor(a.Mapping) {
			vendorBound++
		}
	}
	note := "X + Y > Z"
	if vendorBound > 0 {
		note = plural(vendorBound, "of them waits", "of them wait") + " on " + map[bool]string{true: "its vendor", false: "their vendors"}[vendorBound == 1]
	}
	sv.Cards = append(sv.Cards, summaryCard{strconv.Itoa(v.Counts[statusAtRisk]), "At risk", note, "risk"})
	if n := v.Counts[statusUnknown]; n > 0 {
		sv.Cards = append(sv.Cards, summaryCard{strconv.Itoa(n), "Unknown", "a missing value decides it", "unk"})
	}
	if n := v.Counts[statusMitigated]; n > 0 {
		sv.Cards = append(sv.Cards, summaryCard{strconv.Itoa(n), "Mitigated", "for clients with post-quantum support", "ok"})
	}
	if n := v.Counts[statusNotAtRisk]; n > 0 {
		sv.Cards = append(sv.Cards, summaryCard{strconv.Itoa(n), "Not at risk", "migration finishes in time", "ok"})
	}
	naNote := "unreachable or incomplete"
	if len(r.NotAssessed) > 0 {
		allDown := true
		for _, a := range r.NotAssessed {
			allDown = allDown && strings.HasPrefix(a.Problem, "unreachable")
		}
		if allDown {
			naNote = "unreachable at scan time"
		}
	}
	sv.Cards = append(sv.Cards, summaryCard{strconv.Itoa(c.NotAssessed), "Not assessed", naNote, "na"})
	compNote := "TLS targets in the mapping file"
	if c.CloudDiscovered > 0 {
		compNote = "TLS targets in the mapping file and the cloud"
	}
	sv.Cards = append(sv.Cards, summaryCard{strconv.Itoa(c.Assessed) + " of " + strconv.Itoa(c.Known()), "Completeness", compNote, "comp"})

	// Highest-risk assets.
	for i, a := range r.Assets {
		if i == summaryRows {
			sv.More = "The full report lists all " + plural(len(r.Assets), "assessed asset", "assessed assets") + "."
			break
		}
		sv.Rows = append(sv.Rows, summaryRowOf(a))
	}

	// Certificates that expire within 30 days.
	if v.CertSoon > 0 {
		var first certRow
		for _, cr := range v.Certs {
			if cr.DaysClass == "risk" && cr.Days != "expired" && (first.Target == "" || cr.Cert.NotAfter.Before(first.Cert.NotAfter)) {
				first = cr
			}
		}
		sv.CertNote = plural(v.CertSoon, "certificate expires", "certificates expire") + " within 30 days of the scan, the first on " +
			first.Cert.NotAfter.UTC().Format("2006-01-02") + " (operational, not quantum)."
	}
	if v.CertExpired > 0 {
		sv.CertNote = strings.TrimSpace(plural(v.CertExpired, "certificate has", "certificates have") + " expired (operational, not quantum). " + sv.CertNote)
	}
	return sv
}

func oneDecimal(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func summaryRowOf(a Asset) summaryRow {
	m := a.Mapping
	row := summaryRow{System: m.System, Service: m.Service, Sensitivity: dash(m.DataClassification), Third: "In-house", Constraint: strings.TrimSpace(m.Constraints)}
	if isVendor(m) {
		row.Third = strings.TrimSpace(m.ThirdParty)
	} else if strings.TrimSpace(m.ThirdParty) == "" {
		row.Third = "Not stated"
	}
	mo := a.Mosca
	row.Status = map[string]string{statusAtRisk: "At risk", statusNotAtRisk: "Not at risk", statusMitigated: "Mitigated", statusUnknown: "Unknown"}[mo.Status]
	row.Class = map[string]string{statusAtRisk: "risk", statusNotAtRisk: "ok", statusMitigated: "ok", statusUnknown: "unk"}[mo.Status]
	if mo.Y == nil {
		row.StatusNote = "Migration time unknown"
	}
	switch {
	case mo.Status == statusMitigated:
		row.Exposure, row.ExposureNote = "Older clients only", "clients without post-quantum support"
	case mo.Margin == nil:
		row.Exposure, row.ExposureNote = "Unknown", "depends on the missing value"
	case *mo.Margin <= 0:
		row.Exposure = "None"
	case mo.MarginIsLowerBound:
		row.Exposure = "at least " + oneDecimal(*mo.Margin) + " years"
	case mo.YAssumption:
		row.Exposure = "about " + oneDecimal(*mo.Margin) + " years"
		row.ExposureNote = "assumes " + plural0(*mo.Y, "year") + " to migrate"
	default:
		row.Exposure = oneDecimal(*mo.Margin) + " years"
	}
	row.Do = plainAction(a)
	return row
}

// plural0 prints "1 year", "0.5 years", "3 years".
func plural0(v float64, unit string) string {
	if v == 1 {
		return "1 " + unit
	}
	return num(v) + " " + unit + "s"
}

// plainAction is the summary's "What to do", in plain language.
func plainAction(a Asset) string {
	var old []string
	for _, v := range a.VersionsAccepted {
		if v == "TLS 1.0" || v == "TLS 1.1" {
			old = append(old, strings.TrimPrefix(v, "TLS "))
		}
	}
	legacy := ""
	switch {
	case len(old) > 0:
		legacy = "switch off old protocols (TLS " + strings.Join(old, ", ") + ")"
	case a.Legacy == "yes":
		legacy = "remove weak cipher suites"
	}
	var s string
	ag := a.AgilityIndicative
	switch {
	case a.Mosca.Status == statusMitigated:
		s = "No change now; track how many clients support it"
	case a.KeyExchange == "hybrid":
		s = "No change needed for key exchange"
	case ag != nil && ag.Level == agilityVendorBound:
		s = "Get a dated plan from the vendor"
	case ag != nil && ag.Level == agilityUnknown:
		s = "Record who runs it and how long migration takes"
	case hasFinding(a, "key_exchange", "No TLS 1.3"):
		s = "Upgrade to TLS 1.3, then turn on post-quantum key exchange"
	case len(a.Agility) > 0:
		s = "Switch to a TLS policy with post-quantum key exchange"
	default:
		s = "Turn on post-quantum key exchange; may need a software upgrade"
	}
	if legacy != "" {
		s += "; " + legacy
	}
	return s + "."
}
