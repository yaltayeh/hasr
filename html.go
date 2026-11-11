package main

import (
	"html/template"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// clauseInfo is one section of the report. Text and Items quote the author's
// unofficial English translation verbatim (DECISIONS.md, "Clause text"); the
// official text is the Arabic circular. Title, Provides and Institution are
// Hasr's own wording. PROVISIONAL wording, for the author's review.
type clauseInfo struct {
	N     int
	Ar    string // the circular's own numbering, in Arabic
	Title string
	Due   string
	// DueDate is the last day of the deadline (YYYY-MM-DD), or empty when the circular sets none.
	DueDate     string
	Text        string   // unofficial translation, verbatim
	Items       []string // Clause 2's sub-items, verbatim
	Provides    []string
	Institution []string
}

var clauses = []clauseInfo{
	{
		N: 1, Ar: "أولًا", Title: "Enterprise quantum-risk assessment", Due: "End of Q1 2027", DueDate: "2027-03-31",
		Text: "Conduct an enterprise-level assessment of the risks associated with quantum computing, in line with the institution's enterprise risk management procedures, and set action plans to address the risks resulting from the assessment, provided that they cover, without limitation, operational, legal, regulatory and strategic risks, including the workforce. Due: end of Q1 2027.",
		Provides: []string{
			"Technical input for the assessment: for each assessed TLS endpoint, whether its key exchange is quantum-vulnerable, whether it still accepts legacy protocols or weak cipher suites, and its Mosca margin (Clause 2).",
		},
		Institution: []string{
			"Carry out the enterprise-level assessment within its own risk management procedures.",
			"Assess the operational, legal, regulatory, strategic and workforce risks; Hasr does not cover these.",
			"Set the action plans.",
		},
	},
	{
		N: 2, Ar: "ثانيًا", Title: "Inventory and classification of cryptographic assets", Due: "End of Q4 2026", DueDate: "2026-12-31",
		Text: "Ensure the accuracy and comprehensiveness of the procedures for inventorying and classifying all of the institution's cryptographic assets by the end of Q4 2026, taking into account, at a minimum, the following:",
		Items: []string{
			"2a. Identifying the data, systems and services associated with the cryptographic assets, and classifying them by sensitivity and by priority for migration to quantum-resistant cryptographic solutions.",
			"2b. Assessing the level of crypto-agility of priority assets, and identifying constraints, challenges and third-party dependencies.",
		},
		Provides: []string{
			"Automatic discovery of the cryptography of each TLS endpoint it is given, from ordinary handshakes.",
			"Links to systems, services, owners, data classification, constraints and third parties, from the mapping file.",
			"Migration priority from Mosca's inequality (X + Y > Z).",
			"Evidence of completeness: the completeness figure, and the lists of targets that need owner input, were mapped but not scanned, or could not be assessed, plus the scanner's stated limits.",
		},
		Institution: []string{
			"Keep the target list and the mapping file complete and correct: owners, classification, shelf life, migration time, third parties.",
			"Inventory cryptography Hasr does not reach in this version: other protocols, applications and code, key stores and HSMs, cloud services.",
			"Assess crypto-agility. Hasr's rating is planned; the scan's \"no TLS 1.3\" reason is evidence for it.",
		},
	},
	{
		N: 3, Ar: "ثالثًا", Title: "Plans to reach the required crypto-agility", Due: "No date in the circular",
		Text: "Set plans and initiatives to reach the required level of crypto-agility, or suitable alternative solutions, for all priority assets, consistent with the outputs of Clause 2.",
		Provides: []string{
			"A recommended action for each finding, listed in priority order.",
		},
		Institution: []string{
			"Turn the actions into plans and initiatives: ownership, budget, schedule and vendor engagement.",
			"Choose alternative solutions where migration is not possible.",
		},
	},
	{
		N: 4, Ar: "رابعًا", Title: "Standing monitoring by committees", Due: "No date in the circular",
		Text: "Include quantum computing risks as a standing item for periodic monitoring within the work of the information security supervisory committee and the board risk committee (where applicable), and escalate challenges and recommendations to the board or its equivalent.",
		Provides: []string{
			"Repeatable scans: the same two commands produce a new report at any time, and each scan's JSON is kept as evidence.",
			"Tracking changes between scans is planned; it is not in this version.",
		},
		Institution: []string{
			"Put quantum-computing risk on the committees' standing agenda and set the monitoring cadence.",
			"Escalate challenges and recommendations to the board.",
		},
	},
}

// circular holds the parts of the author's unofficial translation printed
// outside the clauses (DECISIONS.md, "Translation review"). The rest of the
// preamble and the closing are not printed.
var circular = struct{ Title, Lead, Distribution string }{
	Title:        "Raising the level of operational resilience to address quantum computing risks",
	Lead:         "Accordingly, financial institutions are required to take the following actions:",
	Distribution: "all banks operating in the Kingdom; credit information companies; finance companies operating in the Kingdom; payment services companies operating in the Kingdom; entities supporting financing activity licensed by the Central Bank.",
}

// clauseCoverage is the short form of each clause for the "Clause coverage"
// table: what Hasr covers and what the institution must do, in phrases. The
// full lists stay in the SAMA Circular section of the appendix.
var clauseCoverage = map[int]struct{ Short, Covers, Must string }{
	1: {"Enterprise risk assessment",
		"Technical input: quantum-vulnerable key exchange, legacy protocols, Mosca margin per endpoint",
		"Run the enterprise assessment; cover operational, legal, regulatory, strategic and workforce risks; set action plans"},
	2: {"Inventory and classification",
		"TLS endpoint discovery; links to systems, owners and classification; Mosca priority; completeness evidence",
		"Keep the target list and mapping complete; inventory other cryptography; assess crypto-agility"},
	3: {"Crypto-agility plans",
		"A recommended action per finding, in priority order",
		"Turn actions into plans (owner, budget, schedule, vendors); choose alternatives where migration is not possible"},
	4: {"Committee monitoring",
		"Repeatable scans; each scan's JSON kept as evidence",
		"Make quantum risk a standing agenda item; set the cadence; escalate to the board"},
}

// glossEntry is one explanation. It appears in an ⓘ tooltip next to the term
// and in the appendix's Glossary, so it also prints.
type glossEntry struct{ ID, Term, Text string }

var glossary = []glossEntry{
	{"mosca", "Mosca's inequality", "An asset is at risk when X + Y > Z. X: years the data must stay confidential. Y: years to migrate. Z: the time until the quantum threat or a regulatory deadline, in years."},
	{"margin", "Margin", "X + Y − Z, in years. Above 0, migration would finish after the deadline, so the asset is at risk. The bar runs from −10 to +10 years; larger values are pinned at the edge. \"≥\" marks a lower bound: when Y is unknown the margin is at least X − Z, since Y cannot be negative; a dashed tail on the bar shows it."},
	{"status", "Status", "At risk: margin above 0, or, when Y is unknown, X − Z above 0, so the asset is at risk whatever Y is. Not at risk: margin 0 or below. Mitigated for PQ-capable clients: hybrid key exchange is available, but clients without post-quantum support still get classical key exchange. Unknown: a value needed for the margin is missing and the known values do not already show the asset at risk."},
	{"kex", "Key exchange", "How the TLS session key is agreed. Classical (for example x25519) traffic can be recorded now and decrypted later by a quantum computer. Hybrid (X25519MLKEM768) adds ML-KEM and resists that."},
	{"legacy", "Legacy", "The endpoint still accepts TLS 1.0 or 1.1, or weak cipher suites (RSA key transport, 3DES, RC4)."},
	{"action", "Next action", "The first recommended action for the asset. The row's details list every finding with its action (Clause 3)."},
	{"completeness", "Completeness", "TLS targets in the mapping file (plus TLS endpoints found in the cloud, when cloud records are given) that were scanned and fully assessed. Cryptographic assets other than TLS endpoints are out of scope and not counted."},
	{"notassessed", "Not assessed", "Mapped and scanned, but unreachable or incomplete. Never treated as low priority."},
	{"nottested", "Not tested", "What this scanner cannot check, for example SSL 3.0 or finite-field DHE, which Go's TLS library does not implement. Never read as \"not supported\"."},
	{"agility", "Crypto-agility evidence (Clause 2b)", "Hasr's crypto-agility rating is planned and not in this version. Each row's details show the evidence the scan shows today: TLS versions, key-exchange findings, third party and constraints."},
	{"clause1", "Clause 1", "An enterprise-level assessment of quantum-computing risk within the institution's risk management, with action plans."},
	{"clause2", "Clause 2", "Inventory and classification of all cryptographic assets: link them to data, systems and services and set migration priority (2a); assess crypto-agility, constraints and third parties (2b)."},
	{"clause3", "Clause 3", "Plans and initiatives to reach the required crypto-agility, or alternatives, for all priority assets."},
	{"clause4", "Clause 4", "Quantum-computing risk as a standing item for the information-security and board risk committees, with escalation to the board."},
}

func glossaryText(id string) glossEntry {
	for _, g := range glossary {
		if g.ID == id {
			return g
		}
	}
	return glossEntry{ID: id, Term: id}
}

type htmlView struct {
	RiskReport
	Circular struct{ Title, Lead, Distribution string }
	Clauses  []clauseInfo
	Glossary []glossEntry
	Counts   map[string]int
	CSS      template.CSS
	Headline string
	// Segments is the completeness bar: one segment per status, sized by its count.
	Segments []segment
	// Probes is the per-target probe evidence from the scan, for the appendix.
	Probes []probeGroup
	// LowerBound counts at-risk assets whose margin is a lower bound (Y unknown).
	LowerBound int
	// AskVendor and AskOwner are assessed assets whose Y is missing, by whom to ask.
	AskVendor, AskOwner []Asset
	// DefaultsNote says what the default X and Z imply, or is empty.
	DefaultsNote string
	// Coverage is one row per clause: its status in this scan and the days left.
	Coverage []coverageRow
}

// coverageRow is one clause in the "Clause coverage" table.
type coverageRow struct {
	clauseInfo
	Short, Covers, Must string
	// Left is "50 days left" or "3 days overdue", counted from the scan date; empty without a due date.
	Left, LeftClass string
	// Status is the clause's state in this scan, with its colour class and a one-line note.
	Status, StatusClass, Note string
}

// daysLeft counts whole days from the scan date to a due date (both in UTC).
func daysLeft(scan time.Time, due string) (int, bool) {
	d, err := time.Parse("2006-01-02", due)
	if err != nil || scan.IsZero() {
		return 0, false
	}
	y, m, dd := scan.UTC().Date()
	return int(d.Sub(time.Date(y, m, dd, 0, 0, 0, 0, time.UTC)).Hours() / 24), true
}

// coverage builds the clause coverage rows from the report (DECISIONS.md,
// "Expert review, group 2").
func coverage(r RiskReport, v htmlView) []coverageRow {
	c := r.Completeness
	actions, withActions := 0, 0
	for _, a := range r.Assets {
		actions += len(a.Findings)
		if len(a.Findings) > 0 {
			withActions++
		}
	}
	var rows []coverageRow
	for _, ci := range clauses {
		cv := clauseCoverage[ci.N]
		row := coverageRow{clauseInfo: ci, Short: cv.Short, Covers: cv.Covers, Must: cv.Must, StatusClass: "neutral"}
		if n, ok := daysLeft(r.Inputs.ScanGeneratedAt, ci.DueDate); ok {
			switch {
			case n < 0:
				row.Left, row.LeftClass = plural(-n, "day", "days")+" overdue", "risk"
			case n <= 90:
				row.Left, row.LeftClass = plural(n, "day", "days")+" left", "unk"
			default:
				row.Left, row.LeftClass = plural(n, "day", "days")+" left", "neutral"
			}
		}
		switch ci.N {
		case 1:
			if c.Assessed == 0 {
				row.Status, row.StatusClass, row.Note = "No input yet", "na", "No TLS endpoint was fully assessed."
			} else {
				row.Status, row.Note = "Input provided", "Technical input for "+plural(c.Assessed, "assessed endpoint", "assessed endpoints")+". The assessment itself is the institution's."
			}
		case 2:
			parts := []string{"TLS only", strconv.Itoa(c.Assessed) + " of " + strconv.Itoa(c.Known()) + " TLS targets assessed"}
			if c.NotAssessed > 0 {
				parts = append(parts, plural(c.NotAssessed, "not assessed", "not assessed"))
			}
			if c.NeedsOwnerInput > 0 {
				parts = append(parts, plural(c.NeedsOwnerInput, "needs owner input", "need owner input"))
			}
			if c.MappedNotScanned > 0 {
				parts = append(parts, plural(c.MappedNotScanned, "mapped, not scanned", "mapped, not scanned"))
			}
			if c.CloudDiscovered > 0 {
				parts = append(parts, plural(c.CloudDiscovered, "found in the cloud only", "found in the cloud only"))
			}
			if n := len(v.AskVendor) + len(v.AskOwner); n > 0 {
				parts = append(parts, plural(n, "value missing", "values missing"))
			}
			row.Status, row.StatusClass, row.Note = "Partial", "unk", strings.Join(parts, "; ")+"."
		case 3:
			if actions == 0 {
				row.Status, row.Note = "No actions", "No finding needs an action in this scan."
			} else {
				row.Status, row.Note = "Actions proposed", plural(actions, "recommended action", "recommended actions")+" across "+plural(withActions, "asset", "assets")+". Plans, budget and schedule are the institution's."
			}
		case 4:
			row.Status, row.Note = "Evidence repeatable", "The same two commands rebuild this report. Comparison with the previous scan is not built yet."
		}
		rows = append(rows, row)
	}
	return rows
}

type segment struct {
	Class string
	N     int
}

type probeGroup struct {
	Target string
	Rows   []probeRow
}

type probeRow struct {
	Offer, Result, Negotiated, Detail string
}

// probeOffers names each probe's offer in the Method paragraph's words.
var probeOffers = map[string]string{
	"default":        "the default offer",
	"hybrid_only":    "hybrid key exchange only",
	"classical_only": "classical key exchange only",
	"max_tls12":      "TLS 1.2 at most",
	"tls11_only":     "TLS 1.1 only",
	"tls10_only":     "TLS 1.0 only",
	"tls12_weak":     "TLS 1.2 with weak suites only",
}

// writeHTML renders the report. targets are the scan's targets, for the probe
// evidence in the appendix; they add nothing to the report's data.
func writeHTML(w io.Writer, r RiskReport, targets []Target) error {
	v := htmlView{RiskReport: r, Circular: circular, Clauses: clauses, Glossary: glossary, Counts: map[string]int{}, CSS: template.CSS(reportCSS)}
	for _, a := range r.Assets {
		v.Counts[a.Mosca.Status]++
		if a.Mosca.Status == statusAtRisk && a.Mosca.MarginIsLowerBound {
			v.LowerBound++
		}
		switch a.Mosca.Flag {
		case "":
		case "Y unknown: ask vendor":
			v.AskVendor = append(v.AskVendor, a)
		default:
			v.AskOwner = append(v.AskOwner, a)
		}
	}
	v.DefaultsNote = defaultsNote(r.Policy)
	v.Coverage = coverage(r, v)
	for _, list := range [][]Asset{r.Assets, r.NeedsOwnerInput, r.NotAssessed} {
		for _, a := range list {
			if a.Legacy == "yes" {
				v.Counts["legacy"]++
			}
		}
	}
	for _, s := range []struct{ status, class string }{
		{statusAtRisk, "risk"}, {statusUnknown, "unk"}, {statusMitigated, "ok"}, {statusNotAtRisk, "ok"},
	} {
		if n := v.Counts[s.status]; n > 0 {
			v.Segments = append(v.Segments, segment{s.class, n})
		}
	}
	if n := r.Completeness.Known() - r.Completeness.Assessed; n > 0 {
		v.Segments = append(v.Segments, segment{"na", n})
	}
	v.Headline = headline(r, v.Counts)
	for _, t := range targets {
		g := probeGroup{Target: t.Target}
		for _, p := range t.Probes {
			if p.Result == resultNotTested {
				continue
			}
			row := probeRow{Offer: p.ID, Result: p.Result, Negotiated: "—", Detail: p.Detail}
			if o, ok := probeOffers[p.ID]; ok {
				row.Offer = o
			}
			if n := p.Negotiated; n != nil {
				parts := []string{n.Version, n.CipherSuite.Name}
				if n.Group != nil {
					parts = append(parts, n.Group.Name)
				}
				row.Negotiated = strings.Join(parts, " · ")
			}
			g.Rows = append(g.Rows, row)
		}
		v.Probes = append(v.Probes, g)
	}
	return reportTemplate.Execute(w, v)
}

// plural returns "1 target" or "2 targets".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// headline is the first screen's one-paragraph answer, built from the counts.
func headline(r RiskReport, counts map[string]int) string {
	c := r.Completeness
	var s []string
	switch atRisk := counts[statusAtRisk]; {
	case c.Assessed == 0:
		s = append(s, "No mapped target was fully assessed.")
	case atRisk == 0:
		s = append(s, "None of the "+plural(c.Assessed, "assessed TLS endpoint", "assessed TLS endpoints")+" is at risk.")
	default:
		verb := " are"
		if atRisk == 1 {
			verb = " is"
		}
		s = append(s, strconv.Itoa(atRisk)+" of "+plural(c.Assessed, "assessed TLS endpoint", "assessed TLS endpoints")+verb+" at risk.")
	}
	if n := counts[statusUnknown]; n > 0 {
		s = append(s, map[bool]string{true: "1 has", false: strconv.Itoa(n) + " have"}[n == 1]+" unknown priority.")
	}
	if n := c.NotAssessed; n > 0 {
		s = append(s, plural(n, "mapped TLS endpoint", "mapped TLS endpoints")+" could not be assessed.")
	}
	if n := c.NeedsOwnerInput; n > 0 {
		s = append(s, plural(n, "scanned target needs", "scanned targets need")+" owner input.")
	}
	if n := c.MappedNotScanned; n > 0 {
		s = append(s, plural(n, "mapped target was", "mapped targets were")+" not scanned.")
	}
	if n := c.CloudDiscovered; n > 0 {
		s = append(s, plural(n, "endpoint found in the cloud is", "endpoints found in the cloud are")+" not in the target list.")
	}
	return strings.Join(s, " ")
}

// defaultsNote says what the policy's defaults imply: when a level's default X
// is already larger than Z, every endpoint of that level with classical key
// exchange is at risk whatever its Y. Empty when no level is in that case.
func defaultsNote(p Policy) string {
	if p.Z.Years == nil {
		return ""
	}
	z := *p.Z.Years
	var labels []string
	xs := map[float64]bool{}
	for _, l := range p.ClassificationLevels {
		if x := l.ShelfLife.Years; x != nil && *x > z {
			labels = append(labels, l.Label)
			xs[*x] = true
		}
	}
	if len(labels) == 0 {
		return ""
	}
	list := labels[0]
	if n := len(labels); n > 1 {
		list = strings.Join(labels[:n-1], ", ") + " and " + labels[n-1]
	}
	x := "X for " + list
	if len(xs) == 1 {
		for v := range xs {
			x = "X = " + num(v) + " for " + list
		}
	}
	return "With " + x + " and Z = " + num(z) + ", X is already larger than Z. So every " + list +
		" endpoint with classical key exchange is at risk, whatever its Y. The status confirms exposure; the order within At risk comes from sensitivity, legacy protocols, third-party dependency and margin. A shorter X for an entry needs a per-entry value with its own source."
}

// marginScale is the margin bar's half-width in years; larger margins are pinned at the edge.
const marginScale = 10.0

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"years": func(v *float64) string {
		if v == nil {
			return "—"
		}
		return num(*v)
	},
	"signed": signedYears,
	// margin is the margin column's value: "≥ +5.86" when it is a lower bound.
	"margin": func(m Mosca) string {
		s := signedYears(m.Margin)
		if m.MarginIsLowerBound {
			return "≥ " + s
		}
		return s
	},
	// tail is the dashed extension of a lower-bound bar, from its end to the edge.
	"tail": func(m *float64) template.CSS {
		if m == nil || *m <= 0 {
			return "width:0"
		}
		w := math.Min(*m/marginScale, 1) * 50
		return template.CSS("left:" + strconv.FormatFloat(50+w, 'f', 1, 64) + "%;width:" + strconv.FormatFloat(50-w, 'f', 1, 64) + "%")
	},
	// xyz is the margin's inputs in one line: "X 10 · Y ? · Z 4.14".
	"xyz": func(m Mosca) string {
		v := func(p *float64) string {
			if p == nil {
				return "?"
			}
			return num(*p)
		}
		return "X " + v(m.X) + " · Y " + v(m.Y) + " · Z " + v(m.Z)
	},
	"src": func(s Sourced) string {
		if s.Years == nil {
			return "not set"
		}
		return s.Source
	},
	// status is the badge label; a mitigated asset's qualifier is a sub-line (statusSub).
	"status": func(s string) string {
		return map[string]string{
			statusAtRisk: "At risk", statusNotAtRisk: "Not at risk",
			statusMitigated: "Mitigated", statusUnknown: "Unknown",
		}[s]
	},
	"statusSub": func(s string) string {
		if s == statusMitigated {
			return "for PQ-capable clients"
		}
		return ""
	},
	// sc is the colour class of a status: red at risk, amber unknown, green otherwise.
	"sc": func(s string) string {
		switch s {
		case statusAtRisk:
			return "risk"
		case statusNotAtRisk, statusMitigated:
			return "ok"
		}
		return "unk"
	},
	// kexc and legc colour the key-exchange and legacy tags on the same scale.
	"kexc": func(k string) string { return riskClass(k == "classical", k == "hybrid") },
	"legc": func(l string) string { return riskClass(l == "yes", l == "no") },
	"resc": func(r string) string {
		if r == resultError {
			return "na"
		}
		return "neutral"
	},
	// bar places the margin bar: from the zero line, right for a positive margin, left for a negative one.
	"bar": func(m *float64) template.CSS {
		if m == nil || *m == 0 {
			return "width:0"
		}
		w := math.Min(math.Abs(*m)/marginScale, 1) * 50
		side := "left"
		if *m < 0 {
			side = "right"
		}
		return template.CSS(side + ":50%;width:" + strconv.FormatFloat(w, 'f', 1, 64) + "%")
	},
	"gloss":              glossaryText,
	"plural":             plural,
	"disagreementCauses": func() string { return disagreementCauses },
	"join":               strings.Join,
	"hasPrefix":          strings.HasPrefix,
	"versions":           shortVersions,
	"short":              shortRef,
	"key":                func(pk PublicKey) string { return pk.keyLabel() },
	"when":               func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"day":                func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"dash":               dash,
	"slice3":             func(a, b, c []Asset) [][]Asset { return [][]Asset{a, b, c} },
	"more":               func(fs []Finding) int { return len(fs) - 1 },
}).Parse(reportHTML))

// signedYears prints a margin with its sign: +5.86, −1, 0, or — when unknown.
func signedYears(v *float64) string {
	switch {
	case v == nil:
		return "—"
	case *v > 0:
		return "+" + num(*v)
	case *v < 0:
		return "−" + num(-*v)
	}
	return "0"
}

// num prints a number of years without float noise: 4.15, 10, 0.5.
func num(v float64) string { return strconv.FormatFloat(round2(v), 'f', -1, 64) }

// riskClass is red for a risky value, green for a safe one, amber otherwise (unknown).
func riskClass(risky, safe bool) string {
	switch {
	case risky:
		return "risk"
	case safe:
		return "ok"
	}
	return "unk"
}

// Icons are inline SVG (no external resources). Every chip also carries a
// text label: colour is never the only signal.
const reportIcons = `{{define "i-risk"}}<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 2.5 20h19L12 3z"/><path d="M12 10v4"/><path d="M12 17.2v.1"/></svg>{{end}}` +
	`{{define "i-unk"}}<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9.5"/><path d="M9.5 9.3a2.6 2.6 0 0 1 5 .9c0 1.7-2.5 2.3-2.5 3.8"/><path d="M12 17.2v.1"/></svg>{{end}}` +
	`{{define "i-ok"}}<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9.5"/><path d="m7.8 12.3 2.8 2.8 5.6-5.8"/></svg>{{end}}` +
	`{{define "i-na"}}<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9.5" stroke-dasharray="3 3"/><path d="M8 12h8"/></svg>{{end}}` +
	`{{define "i-chev"}}<svg class="ic chev" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>{{end}}` +
	`{{define "statusChip"}}<span class="chip c-{{sc .}}">{{if eq . "at_risk"}}{{template "i-risk"}}{{else if eq . "unknown"}}{{template "i-unk"}}{{else}}{{template "i-ok"}}{{end}}{{status .}}</span>{{with statusSub .}}<span class="note">{{.}}</span>{{end}}{{end}}` +
	// info is the ⓘ next to a term: the explanation shows on hover, on tap and on keyboard focus (CSS only).
	`{{define "info"}}{{with gloss .}}<span class="info" tabindex="0" role="note" aria-label="{{.Term}}: {{.Text}}"><span class="i" aria-hidden="true">ⓘ</span><span class="tip" aria-hidden="true"><strong>{{.Term}}.</strong> {{.Text}}</span></span>{{end}}{{end}}` +
	`{{define "links"}}{{range .}}<span class="note link"><a href="{{.}}" rel="noopener noreferrer">{{.}}</a></span>{{end}}{{end}}` +
	`{{define "assume"}}<span class="note assume">assumption; override per entry</span>{{end}}` +
	`{{define "findings"}}<table class="tbl inner"><thead><tr><th class="area">Area</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>{{range .}}<tr><td><span class="tag c-neutral mono">{{.Area}}</span></td><td>{{.Finding}}</td><td class="muted">{{.Action}}</td></tr>{{end}}</tbody></table>{{end}}`

const reportHTML = reportIcons + `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Hasr · SAMA Circular 482021280 · {{day .Inputs.ScanGeneratedAt}}</title>
<style>{{.CSS}}</style>
<style>@page{@bottom-left{content:"Hasr · SAMA Circular 482021280 · {{day .Inputs.ScanGeneratedAt}}";font:8.5pt -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;color:#575073}}</style>
</head>
<body>
<main class="wrap">

<header class="top">
  <h1>Hasr · <a href="#sama">SAMA Circular 482021280</a> · {{day .Inputs.ScanGeneratedAt}}</h1>
  <div class="printbtns"><button type="button" id="print-summary">Print summary</button><button type="button" id="print-full">Print full report</button></div>
</header>
<p class="headline">{{.Headline}}</p>
<p class="scope"><strong>Scope: TLS endpoints only{{if .Inputs.Cloud}}, from the scan and the cloud load-balancer records{{end}}.</strong> Not covered: SSH, VPN, HSMs and key stores, application code, databases. The figures are not a measure of all cryptographic assets.</p>
{{if .MissingValues}}<div class="banner"><strong>Mosca values not set:</strong> {{join .MissingValues "; "}}. Until they are provided, the at-risk status is "Unknown" wherever a missing value is needed.</div>{{end}}

<section class="cards" aria-label="Status">
  <div class="card b-risk"><span class="cnum t-risk">{{index .Counts "at_risk"}}</span><span class="clabel t-risk">{{template "i-risk"}}At risk</span><span class="csub">X + Y &gt; Z{{with .LowerBound}} ({{.}} with Y unknown){{end}}</span></div>
  <div class="card b-unk"><span class="cnum t-unk">{{index .Counts "unknown"}}</span><span class="clabel t-unk">{{template "i-unk"}}Unknown</span><span class="csub">a value is missing; the outcome depends on it</span></div>
  <div class="card"><span class="cnum t-ok">{{index .Counts "mitigated_pq_clients"}}</span><span class="clabel t-ok">{{template "i-ok"}}Mitigated</span><span class="csub">for PQ-capable clients</span></div>
  <div class="card"><span class="cnum">{{index .Counts "not_at_risk"}}</span><span class="clabel t-ok">{{template "i-ok"}}Not at risk</span><span class="csub">X + Y ≤ Z, or hybrid only</span></div>
  <div class="card"><span class="cnum t-na">{{.Completeness.NotAssessed}}</span><span class="clabel t-na">{{template "i-na"}}Not assessed</span><span class="csub">unreachable or incomplete</span></div>
  <div class="card compcard">
    <span class="cnum sm">{{.Completeness.Assessed}} of {{.Completeness.Known}}</span>
    <div class="segs" role="img" aria-label="{{.Completeness.Assessed}} of {{.Completeness.Known}} TLS targets assessed">{{range .Segments}}<span class="seg s-{{.Class}}" style="flex-grow:{{.N}}"></span>{{end}}</div>
    <span class="clabel">Completeness {{template "info" "completeness"}}</span>
    <span class="csub">{{if .Completeness.CloudDiscovered}}TLS targets in the mapping file and the cloud, assessed{{else}}TLS targets in the mapping file, assessed{{end}}</span>
  </div>
</section>
{{if or (index .Counts "legacy") .AskVendor .AskOwner}}<p class="legacyline">{{with index .Counts "legacy"}}<span class="lline"><span class="tag c-risk">{{.}}</span>{{if eq . 1}}target accepts{{else}}targets accept{{end}} legacy protocols or weak suites {{template "info" "legacy"}}</span>{{end}}{{with .AskVendor}}<a class="lline" href="#missing-entry-values"><span class="tag c-unk">{{len .}}</span>{{if eq (len .) 1}}target needs a value from its vendor{{else}}targets need a value from their vendors{{end}} (Y)</a>{{end}}{{with .AskOwner}}<a class="lline" href="#missing-entry-values"><span class="tag c-unk">{{len .}}</span>{{if eq (len .) 1}}target needs a value from its owner{{else}}targets need a value from their owners{{end}} (Y)</a>{{end}}</p>{{end}}

<section id="priority" class="block">
  <div class="sechead"><h2>Migration priority</h2><a class="tag c-clause" href="#sama-clause-2">Clause 2a</a>{{template "info" "mosca"}}</div>
  {{if .Assets}}
  <div class="panel box"><table class="tbl priority">
    <thead><tr><th>Target</th><th>System</th><th>Status {{template "info" "status"}}</th><th>Margin {{template "info" "margin"}}</th><th>Key exchange {{template "info" "kex"}}</th><th>Legacy {{template "info" "legacy"}}</th><th>Next action {{template "info" "action"}}</th></tr></thead>
    {{range $i, $a := .Assets}}
    <tbody class="asset{{if eq $a.Mosca.Status "at_risk"}} row-risk{{end}}">
      <tr>
        <td class="mono nowrap">{{$a.Target}}</td>
        <td><span class="strong">{{$a.Mapping.System}}</span>{{with $a.Mapping.Service}}<span class="note">{{.}}</span>{{end}}<span class="note">{{dash $a.Mapping.DataClassification}}{{with $a.Mapping.ThirdParty}} · {{.}}{{end}}</span></td>
        <td>{{template "statusChip" $a.Mosca.Status}}{{with $a.Mosca.Flag}}<span class="tag c-unk flag">{{.}}</span>{{end}}</td>
        <td class="margin">
          <div class="mrow"><span class="mval t-{{sc $a.Mosca.Status}}">{{margin $a.Mosca}}</span><span class="track{{if not $a.Mosca.Margin}} empty{{end}}" aria-hidden="true"><span class="zero"></span>{{if $a.Mosca.Margin}}<span class="fill f-{{$a.Mosca.Status}}" style="{{bar $a.Mosca.Margin}}"></span>{{if $a.Mosca.MarginIsLowerBound}}<span class="ext" style="{{tail $a.Mosca.Margin}}"></span>{{end}}{{end}}</span></div>
          <span class="note mono">{{xyz $a.Mosca}}</span>
          {{if $a.Mosca.MarginIsLowerBound}}<span class="note">Lower bound: Y ≥ 0</span>{{end}}
          {{if $a.Mosca.MarginScope}}<span class="note">({{$a.Mosca.MarginScope}})</span>{{end}}
        </td>
        <td><span class="tag c-{{kexc $a.KeyExchange}}">{{$a.KeyExchange}}</span></td>
        <td><span class="tag c-{{legc $a.Legacy}}">{{$a.Legacy}}</span></td>
        <td class="action">{{with $a.Findings}}{{(index . 0).Action}}{{if gt (more .) 0}} <span class="more">+{{more .}} more</span>{{end}}{{else}}—{{end}}</td>
      </tr>
      <tr class="rowdetail"><td colspan="7">
        <details>
          <summary>{{template "i-chev"}}Details: owner, classification, X, Y, Z, findings</summary>
          <div class="facts">
            <dl>
              <dt>Owner</dt><dd>{{dash $a.Mapping.Owner}}{{with index $a.FieldSources "owner"}}<span class="note">from {{.}}</span>{{end}}</dd>
              <dt>Classification</dt><dd>{{dash $a.Mapping.DataClassification}}</dd>
              {{with index $a.FieldSources "system"}}<dt>System</dt><dd><span class="note">from {{.}}</span></dd>{{end}}
              {{with index $a.FieldSources "service"}}<dt>Service</dt><dd><span class="note">from {{.}}</span></dd>{{end}}
              <dt>X</dt><dd>{{years $a.Mosca.X}}<span class="note">{{$a.Mosca.XSource}}</span></dd>
              <dt>Y</dt><dd>{{years $a.Mosca.Y}}<span class="note">{{$a.Mosca.YSource}}</span>{{if $a.Mosca.YAssumption}}{{template "assume"}}{{end}}</dd>
              <dt>Z</dt><dd>{{years $a.Mosca.Z}}</dd>
              {{with $a.Mosca.Notes}}<dt>Status notes</dt><dd>{{range .}}<span class="note">{{.}}</span>{{end}}</dd>{{end}}
            </dl>
            <dl>
              <dt>Third party</dt><dd>{{dash $a.Mapping.ThirdParty}}</dd>
              <dt>Constraints</dt><dd>{{dash $a.Mapping.Constraints}}</dd>
              <dt>TLS versions</dt><dd class="mono">{{versions $a.VersionsAccepted}}</dd>
              {{with $a.Cloud}}<dt>Cloud records</dt><dd>{{range .}}<span class="note">{{.Provider}}: {{.Name}} ({{.Match}} match)</span>{{end}}</dd>{{end}}
              {{with $a.Agility}}<dt>Cloud evidence</dt><dd>{{range .}}<span class="note">{{.}}</span>{{end}}</dd>{{end}}
              <dt>Crypto-agility {{template "info" "agility"}}</dt><dd>{{range $a.Findings}}{{if eq .Area "key_exchange"}}<span class="note">{{.Finding}}</span>{{end}}{{end}}</dd>
            </dl>
          </div>
          {{with $a.Findings}}<div class="box">{{template "findings" .}}</div>{{end}}
        </details>
      </td></tr>
    </tbody>
    {{end}}
  </table></div>
  <p class="legend">Bar: X+Y−Z in years; right of 0 = migration finishes after the deadline. Scale ±10 years. A dashed tail marks a lower bound (Y unknown). Order: at risk, unknown, not at risk, mitigated; within each, sensitivity (highest classification first), then legacy protocols, then third-party dependency, then margin.</p>
  {{else}}<p class="empty">No mapped target was fully assessed.</p>{{end}}
</section>

<section id="completeness" class="block">
  <div class="sechead"><h2>Completeness</h2>{{template "info" "completeness"}}</div>
  <p class="hint"><strong class="ink">{{.Completeness.Assessed}} of {{.Completeness.Known}}</strong> TLS targets {{if .Completeness.CloudDiscovered}}known ({{.Completeness.Mapped}} in the mapping file, plus {{.Completeness.CloudDiscovered}} found in the cloud and not in the target list){{else}}in the mapping file{{end}} were scanned and fully assessed. Out of scope, and not counted: cryptographic assets other than TLS endpoints.</p>
  <div class="counts">
    <a href="#missing-entry-values"><span class="chip c-unk">{{template "i-unk"}}{{len .AskVendor}}</span>Missing values: Y from a vendor</a>
    {{with .AskOwner}}<a href="#missing-entry-values"><span class="chip c-unk">{{template "i-unk"}}{{len .}}</span>Missing values: Y from an owner</a>{{end}}
    <a href="#needs-owner-input"><span class="chip c-unk">{{template "i-unk"}}{{.Completeness.NeedsOwnerInput}}</span>Needs owner input</a>
    <a href="#mapped-not-scanned"><span class="chip c-na">{{template "i-na"}}{{.Completeness.MappedNotScanned}}</span>Mapped but not scanned</a>
    <a href="#not-assessed"><span class="chip c-na">{{template "i-na"}}{{.Completeness.NotAssessed}}</span>Not assessed {{template "info" "notassessed"}}</a>
    <a href="#not-tested"><span class="chip c-na">{{template "i-na"}}{{len .NotTested}}</span>Not tested {{template "info" "nottested"}}</a>
    {{if .Inputs.Cloud}}<a href="#cloud-discovered"><span class="chip c-unk">{{template "i-unk"}}{{.Completeness.CloudDiscovered}}</span>Found in the cloud, not in the target list</a>
    <a href="#disagreements"><span class="chip c-unk">{{template "i-unk"}}{{len .Disagreements}}</span>Scan and cloud records disagree</a>
    <a href="#cloud-limits"><span class="chip c-na">{{template "i-na"}}{{len .CloudLimits}}</span>Not read: stated limits of the cloud collectors</a>{{end}}
  </div>
  <div class="lists">
    <details class="ev" id="missing-entry-values">
      <summary>{{template "i-chev"}}Missing values<span class="meta">{{len .AskVendor}} from vendors · {{len .AskOwner}} from owners</span></summary>
      <div class="evbody">
      {{if or .AskVendor .AskOwner}}
        <p class="hint">Assessed, but Y (migration years) is missing. Hasr never guesses a vendor's timeline. Set <span class="mono">migration_years</span> in the mapping file once the answer comes.</p>
        <div class="box"><table class="tbl">
          <thead><tr><th>Target</th><th>System</th><th>Ask</th><th>Why Y is missing</th><th>Status meanwhile</th></tr></thead>
          <tbody>{{range (slice3 .AskVendor .AskOwner nil)}}{{range .}}<tr><td class="mono nowrap">{{.Target}}</td><td>{{.Mapping.System}}{{with .Mapping.ThirdParty}}<span class="note">{{.}}</span>{{end}}</td><td><span class="tag c-unk">{{.Mosca.Flag}}</span></td><td class="muted small">{{range .Mosca.Notes}}{{if hasPrefix . "Y unknown"}}{{.}}{{end}}{{end}}</td><td>{{template "statusChip" .Mosca.Status}}{{if .Mosca.MarginIsLowerBound}}<span class="note">X − Z = {{signed .Mosca.Margin}} &gt; 0, whatever Y is</span>{{else if eq .Mosca.Status "unknown"}}<span class="note">depends on Y</span>{{end}}</td></tr>{{end}}{{end}}</tbody>
        </table></div>
      {{else}}<p class="empty">None.</p>{{end}}
      </div>
    </details>
    <details class="ev" id="needs-owner-input">
      <summary>{{template "i-chev"}}Needs owner input<span class="meta">{{.Completeness.NeedsOwnerInput}}</span></summary>
      <div class="evbody">
      {{if .NeedsOwnerInput}}
        <p class="hint">Scanned but not in the mapping file: no owner, classification or priority. Priority: unknown.</p>
        <div class="box"><table class="tbl">
          <thead><tr><th>Target</th><th>Key exchange</th><th>Legacy</th><th>TLS versions</th><th>Findings</th></tr></thead>
          <tbody>{{range .NeedsOwnerInput}}<tr><td class="mono nowrap">{{.Target}}</td><td><span class="tag c-{{kexc .KeyExchange}}">{{.KeyExchange}}</span></td><td><span class="tag c-{{legc .Legacy}}">{{.Legacy}}</span></td><td class="mono">{{versions .VersionsAccepted}}</td><td>{{len .Findings}}{{if .Problem}}<span class="note">{{.Problem}}</span>{{end}}</td></tr>{{end}}</tbody>
        </table></div>
        {{range .NeedsOwnerInput}}{{if .Findings}}<p class="sub mono">{{.Target}}</p><div class="box">{{template "findings" .Findings}}</div>{{end}}{{end}}
      {{else}}<p class="empty">None.</p>{{end}}
      </div>
    </details>
    <details class="ev" id="mapped-not-scanned">
      <summary>{{template "i-chev"}}Mapped but not scanned<span class="meta">{{.Completeness.MappedNotScanned}}</span></summary>
      <div class="evbody">
      {{if .MappedNotScanned}}<div class="box"><table class="tbl">
        <thead><tr><th>Target</th><th>System</th><th>Service</th><th>Owner</th></tr></thead>
        <tbody>{{range .MappedNotScanned}}<tr><td class="mono nowrap">{{.Target}}</td><td>{{.System}}</td><td>{{.Service}}</td><td class="muted">{{.Owner}}</td></tr>{{end}}</tbody>
      </table></div>{{else}}<p class="empty">None.</p>{{end}}
      </div>
    </details>
    <details class="ev" id="not-assessed">
      <summary>{{template "i-chev"}}Not assessed<span class="meta">{{.Completeness.NotAssessed}}</span></summary>
      <div class="evbody">
      {{if .NotAssessed}}<div class="box"><table class="tbl">
        <thead><tr><th>Target</th><th>System</th><th>Owner</th><th>Problem</th></tr></thead>
        <tbody>{{range .NotAssessed}}<tr><td class="mono nowrap">{{.Target}}</td><td>{{.Mapping.System}}{{with .Mapping.Service}}<span class="note">{{.}}</span>{{end}}</td><td class="muted">{{.Mapping.Owner}}</td><td class="muted small">{{.Problem}}</td></tr>{{end}}</tbody>
      </table></div>{{else}}<p class="empty">None.</p>{{end}}
      </div>
    </details>
    <details class="ev" id="not-tested">
      <summary>{{template "i-chev"}}Not tested: the scanner's stated limits<span class="meta">{{len .NotTested}}</span></summary>
      <div class="evbody"><ul class="limits">{{range .NotTested}}<li><span class="tag c-na mono">{{.ID}}</span><span>{{.Detail}}</span></li>{{end}}</ul></div>
    </details>
    {{if .Inputs.Cloud}}
    <details class="ev" id="cloud-discovered">
      <summary>{{template "i-chev"}}Found in the cloud, not in the target list<span class="meta">{{.Completeness.CloudDiscovered}}</span></summary>
      <div class="evbody">
      {{if .CloudDiscovered}}
        <p class="hint">Endpoints the cloud records list that no scanned or mapped target matched. Hasr never scans them automatically: review them and add the ones in scope to the mapping file.</p>
        <div class="box"><table class="tbl">
          <thead><tr><th>Provider · scope</th><th>Name</th><th>Hostnames</th><th>Port</th><th>Protocol</th><th>Exposure</th><th>Key exchange</th><th>Legacy</th><th>Policy</th></tr></thead>
          <tbody>{{range .CloudDiscovered}}<tr><td>{{.Provider}} · {{.Scope}}</td><td>{{.Name}}</td><td class="mono">{{join .Hostnames ", "}}</td><td class="num">{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Exposure}}</td>
            {{if .TLS}}<td><span class="tag c-{{kexc .TLS.KeyExchange}}">{{.TLS.KeyExchange}}</span></td><td><span class="tag c-{{legc .TLS.Legacy}}">{{.TLS.Legacy}}</span></td><td class="mono">{{.TLS.Policy.Name}}</td>{{else}}<td colspan="3">{{range .Notes}}<span class="note">{{.}}</span>{{end}}</td>{{end}}</tr>{{end}}</tbody>
        </table></div>
      {{else}}<p class="empty">None.</p>{{end}}
      </div>
    </details>
    <details class="ev" id="disagreements">
      <summary>{{template "i-chev"}}Scan and cloud records disagree<span class="meta">{{len .Disagreements}}</span></summary>
      <div class="evbody">
      {{if .Disagreements}}
        <p class="hint">Possible causes: {{disagreementCauses}}. The worse of the two values counts for priority.</p>
        <div class="box"><table class="tbl">
          <thead><tr><th>Target</th><th>Cloud record</th><th>Field</th><th>Scan saw</th><th>Cloud record says</th><th>Counted</th></tr></thead>
          <tbody>{{range .Disagreements}}<tr><td class="mono nowrap">{{.Target}}</td><td>{{.Provider}} {{.Name}}</td><td class="mono">{{.Field}}</td><td>{{.Scan}}</td><td>{{.Cloud}}</td><td class="strong">{{.Counted}}</td></tr>{{end}}</tbody>
        </table></div>
      {{else}}<p class="empty">None.</p>{{end}}
      </div>
    </details>
    <details class="ev" id="cloud-limits">
      <summary>{{template "i-chev"}}Not read: the cloud collectors' stated limits<span class="meta">{{len .CloudLimits}}</span></summary>
      <div class="evbody"><ul class="limits">{{range .CloudLimits}}<li><span class="tag c-na mono">{{.ID}}</span><span>{{.Detail}}</span></li>{{end}}</ul></div>
    </details>
    {{end}}
  </div>
</section>

<section id="coverage" class="block">
  <div class="sechead"><h2>Clause coverage</h2></div>
  <p class="hint">Days left are counted from the scan date. Clause numbers are Hasr's; the circular's own numbering is shown in Arabic.</p>
  <div class="panel box"><table class="tbl coverage">
    <thead><tr><th>Clause</th><th>Due</th><th>Status in this scan</th><th>Hasr covers</th><th>Institution must</th></tr></thead>
    <tbody>{{range .Coverage}}<tr>
      <td><span class="cl"><a class="tag c-clause" href="#sama-clause-{{.N}}">Clause {{.N}}</a><span class="ar" lang="ar" dir="rtl">{{.Ar}}</span>{{template "info" (printf "clause%d" .N)}}</span><span class="note strong ink">{{.Short}}</span></td>
      <td class="nowrap">{{.Due}}{{if .Left}}<span class="note"><span class="tag c-{{.LeftClass}}">{{.Left}}</span></span>{{end}}</td>
      <td><span class="chip c-{{.StatusClass}}">{{.Status}}</span><span class="note">{{.Note}}</span></td>
      <td>{{.Covers}}</td>
      <td class="muted">{{.Must}}</td>
    </tr>{{end}}</tbody>
  </table></div>
</section>

<section id="appendix" class="block">
  <div class="sechead"><h2>Appendix</h2></div>

  <details class="ev" id="sama">
    <summary>{{template "i-chev"}}SAMA Circular<span class="meta">No. 482021280</span></summary>
    <div class="evbody">
      <dl class="circular">
        <dt>Circular</dt><dd>SAMA Circular No. 482021280, dated 1448/03/14 H (27 August 2026): <strong>{{.Circular.Title}}</strong></dd>
        <dt>Distribution</dt><dd>{{.Circular.Distribution}}</dd>
      </dl>
      <p class="hint">Unofficial translation by the author. The circular's title, distribution and clause texts are quoted from the author's unofficial English translation; the official text is the Arabic circular. The labels "Clause 1–4" and "2a/2b" are Hasr's; the circular numbers its clauses First to Fourth (Clause 1 = <span lang="ar" dir="rtl">أولًا</span>, Clause 2 = <span lang="ar" dir="rtl">ثانيًا</span>, Clause 3 = <span lang="ar" dir="rtl">ثالثًا</span>, Clause 4 = <span lang="ar" dir="rtl">رابعًا</span>) and does not number Clause 2's two items.</p>
      <p class="leadline">{{.Circular.Lead}}</p>
      {{range .Clauses}}
      <div class="clausetext" id="sama-clause-{{.N}}">
        <h3><span class="tag c-clause">Clause {{.N}}</span><span class="ar" lang="ar" dir="rtl">{{.Ar}}</span> {{.Title}}</h3>
        <blockquote class="quote"><p>{{.Text}}</p>{{if .Items}}<ul>{{range .Items}}<li>{{.}}</li>{{end}}</ul>{{end}}</blockquote>
        <div class="two">
          <div><h4>What Hasr provides</h4><ul>{{range .Provides}}<li>{{.}}</li>{{end}}</ul></div>
          <div><h4>What the institution still has to do</h4><ul>{{range .Institution}}<li>{{.}}</li>{{end}}</ul></div>
        </div>
      </div>
      {{end}}
    </div>
  </details>

  <details class="ev" id="glossary">
    <summary>{{template "i-chev"}}Glossary<span class="meta">{{len .Glossary}} terms</span></summary>
    <div class="evbody"><dl class="gloss">{{range .Glossary}}<div class="gi"><dt id="g-{{.ID}}">{{.Term}}</dt><dd>{{.Text}}</dd></div>{{end}}</dl></div>
  </details>

  <details class="ev" id="values">
    <summary>{{template "i-chev"}}Values and sources<span class="meta">{{.Inputs.PolicyFile}}</span></summary>
    <div class="evbody">
      <p class="hint">A value given per entry in the mapping file replaces the default for that entry.</p>
      <div class="box"><table class="tbl values">
        <thead><tr><th>Value</th><th class="num">Years</th><th>Source</th></tr></thead>
        <tbody>
          <tr><td class="strong">Z: the time until the quantum threat or a regulatory deadline</td><td class="num">{{years .Policy.Z.Years}}{{if .Policy.Z.Date}}<span class="note">until {{.Policy.Z.Date}}</span>{{end}}</td><td class="muted">{{if .Policy.Z.Years}}{{.Policy.Z.Source}}{{template "links" .Policy.Z.Links}}{{else}}not set{{end}}</td></tr>
          {{range .Policy.ClassificationLevels}}<tr><td class="strong">Default X: {{.Label}}</td><td class="num">{{years .ShelfLife.Years}}</td><td class="muted">{{src .ShelfLife}}{{template "links" .ShelfLife.Links}}</td></tr>{{end}}
          {{with .Policy.MigrationYearsDefault}}
          <tr><td class="strong">Default Y: already hybrid</td><td class="num">{{years .AlreadyHybrid.Years}}</td><td class="muted">{{src .AlreadyHybrid}}{{template "links" .AlreadyHybrid.Links}}{{if .AlreadyHybrid.Assumption}}{{template "assume"}}{{end}}</td></tr>
          <tr><td class="strong">Default Y: TLS 1.3, classical key exchange</td><td class="num">{{years .TLS13Classical.Years}}</td><td class="muted">{{src .TLS13Classical}}{{template "links" .TLS13Classical.Links}}{{if .TLS13Classical.Assumption}}{{template "assume"}}{{end}}</td></tr>
          <tr><td class="strong">Default Y: no TLS 1.3</td><td class="num">{{years .NoTLS13.Years}}</td><td class="muted">{{src .NoTLS13}}{{template "links" .NoTLS13.Links}}{{if .NoTLS13.Assumption}}{{template "assume"}}{{end}}</td></tr>
          <tr><td class="strong">Default Y: managed TLS policy (cloud)</td><td class="num">{{years .ManagedTLSPolicy.Years}}</td><td class="muted">{{src .ManagedTLSPolicy}}{{template "links" .ManagedTLSPolicy.Links}}{{if .ManagedTLSPolicy.Assumption}}{{template "assume"}}{{end}}</td></tr>
          {{end}}
        </tbody>
      </table></div>
      <p class="hint">Default Y applies only to endpoints whose third_party is "in-house"; a vendor's timeline is never guessed.</p>
      {{with .DefaultsNote}}<p class="implies"><strong>What these defaults imply.</strong> {{.}}</p>{{end}}
    </div>
  </details>

  <details class="ev" id="certificates">
    <summary>{{template "i-chev"}}Certificates</summary>
    <div class="evbody">
      <p class="hint">Listed with their algorithms. No Mosca priority for certificates in this version.</p>
      <div class="box"><table class="tbl">
        <thead><tr><th>Target</th><th>Certificate</th><th>Key</th><th>Signature</th><th>Chain</th><th>Hostname</th><th>Validity</th><th>Not after</th><th>Issuer</th></tr></thead>
        <tbody>
        {{range $list := (slice3 .Assets .NeedsOwnerInput .NotAssessed)}}{{range $a := $list}}{{range $c := $a.Certificates}}
          <tr><td class="mono nowrap">{{$a.Target}}</td><td class="mono">{{short $c.Ref}}</td><td>{{key $c.PublicKey}}</td><td>{{$c.SignatureAlgorithm}}</td><td>{{if $c.Verification.ChainTrusted}}trusted{{else}}not trusted{{with $c.Verification.ChainError}}<span class="note">{{.}}</span>{{end}}{{end}}</td><td class="mono">{{$c.Verification.HostnameMatch}}</td><td>{{$c.Verification.Validity}}</td><td class="mono nowrap">{{day $c.NotAfter}}</td><td class="mono">{{$c.Issuer}}</td></tr>
        {{end}}{{end}}{{end}}
        </tbody>
      </table></div>
    </div>
  </details>

  {{if .Probes}}
  <details class="ev" id="probes">
    <summary>{{template "i-chev"}}Probes<span class="meta">{{len .Probes}} targets</span></summary>
    <div class="evbody probes">
      {{range .Probes}}
      <div>
        <p class="sub mono strong">{{.Target}}</p>
        <div class="box"><table class="tbl inner">
          <thead><tr><th class="offer">Offer</th><th>Result</th><th>Negotiated</th><th>Detail</th></tr></thead>
          <tbody>{{range .Rows}}<tr><td>{{.Offer}}</td><td><span class="tag c-{{resc .Result}}">{{.Result}}</span></td><td class="mono">{{.Negotiated}}</td><td class="dim">{{.Detail}}</td></tr>{{end}}</tbody>
        </table></div>
      </div>
      {{end}}
    </div>
  </details>
  {{end}}

  <details class="ev" id="method">
    <summary>{{template "i-chev"}}Method</summary>
    <div class="evbody"><p>Each target receives a fixed set of ordinary TLS handshakes, each with a different offer: the default offer; hybrid key exchange only; classical key exchange only; TLS 1.2 at most; TLS 1.1 only; TLS 1.0 only; TLS 1.2 with weak suites only. Nothing beyond a handshake is sent, and only targets the institution owns or is authorised to assess may be scanned.</p></div>
  </details>

  <details class="ev" id="inputs">
    <summary>{{template "i-chev"}}Inputs</summary>
    <div class="evbody"><ul>
      <li>Scan: <span class="mono">{{.Inputs.ScanFile}}</span>, {{.Completeness.Scanned}} targets, {{.Inputs.ScanTool.Name}} with {{.Inputs.ScanTool.Go}}; scan run {{when .Inputs.ScanGeneratedAt}}, scan schema {{.Inputs.ScanSchemaVersion}}</li>
      <li>Mapping: <span class="mono">{{.Inputs.MappingFile}}</span>, {{.Completeness.Mapped}} rows</li>
      <li>Policy: <span class="mono">{{.Inputs.PolicyFile}}</span> (classification levels: {{range $i, $l := .Policy.ClassificationLevels}}{{if $i}}, {{end}}{{$l.Label}}{{end}})</li>
      {{range .Inputs.Cloud}}<li>Cloud: <span class="mono">{{.File}}</span>, provider {{.Provider}}, collected {{when .CollectedAt}}; scopes: {{range $i, $s := .Scopes}}{{if $i}}, {{end}}{{$s.Scope}} ({{$s.Status}}){{end}}</li>{{end}}
      <li>Report generated {{when .GeneratedAt}} by Hasr ({{.Tool.Go}}), report schema {{.SchemaVersion}}</li>
    </ul></div>
  </details>

  <details class="ev" id="reproduce">
    <summary>{{template "i-chev"}}How to reproduce</summary>
    <div class="evbody">
      <pre class="cmd">hasr scan [--targets {{.Inputs.MappingFile}}] [host:port ...] &gt; scan.json
{{range .Inputs.Cloud}}collectors/{{.Provider}}/collect.sh -o RAW_DIR --region REGION ...
hasr cloud {{.Provider}} --from RAW_DIR &gt; {{.File}}
{{end}}hasr report --scan scan.json --map {{.Inputs.MappingFile}}{{range .Inputs.Cloud}} --cloud {{.File}}{{end}} --policy {{.Inputs.PolicyFile}}</pre>
      <p class="hint">Keep each scan's JSON with the report as evidence. Tracking changes between scans is planned.</p>
    </div>
  </details>
</section>
</main>
<script>/* Optional. Without it the page works and prints the summary. */
(function(){var h=document.documentElement;h.className+=" js";
function opened(t){for(var n=t;n;n=n.parentElement){if(n.tagName==="DETAILS")n.open=true}}
document.addEventListener("click",function(e){var a=e.target.closest&&e.target.closest('a[href^="#"]');if(a){var t=document.getElementById(a.getAttribute("href").slice(1));if(t)opened(t)}});
if(location.hash){var t0=document.getElementById(location.hash.slice(1));if(t0)opened(t0)}
document.getElementById("print-summary").onclick=function(){window.print()};
document.getElementById("print-full").onclick=function(){var ds=document.querySelectorAll("details"),was=[];
for(var i=0;i<ds.length;i++){was.push(ds[i].open);ds[i].open=true}h.classList.add("print-full");
function back(){for(var i=0;i<ds.length;i++)ds[i].open=was[i];h.classList.remove("print-full");removeEventListener("afterprint",back)}
addEventListener("afterprint",back);window.print()};})();</script>
</body>
</html>
`

const reportCSS = `
:root{color-scheme:light dark;
--bg:#F6F4FB;--surface:#FFFFFF;--raised:#F0ECF9;--ink:#170F2E;--ink-soft:#2C2349;--muted:#463D63;--dim:#575073;--faint:#625A82;--accent:#5537BD;--on-accent:#FFFFFF;
--line:rgba(23,15,46,.13);--line-soft:rgba(23,15,46,.08);--code:#F0ECF9;--tip-bg:#170F2E;--tip-ink:#F2EDFF;
--risk:#B42318;--risk-bg:#FDECEA;--risk-line:#F1B1A9;--unk:#8A5300;--unk-bg:#FFF3DC;--unk-line:#E8BE74;
--ok:#1E6B45;--ok-bg:#E6F4EC;--ok-line:#9BCFB1;--na:#4E4A5E;--na-bg:#EDECF1;--na-line:#C6C2D2}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#0C0627;--surface:#120838;--raised:#160B40;--ink:#F2EDFF;--ink-soft:#D6CCF2;--muted:#BDB0DE;--dim:#A396C9;--faint:#9486BE;--accent:#BFA3FF;--on-accent:#12063A;
--line:rgba(242,237,255,.11);--line-soft:rgba(242,237,255,.065);--code:#0F0830;--tip-bg:#F2EDFF;--tip-ink:#170F2E;
--risk:#FF9F8E;--risk-bg:rgba(255,159,142,.12);--risk-line:rgba(255,159,142,.45);--unk:#F2C46D;--unk-bg:rgba(242,196,109,.11);--unk-line:rgba(242,196,109,.45);
--ok:#86D9AE;--ok-bg:rgba(134,217,174,.11);--ok-line:rgba(134,217,174,.42);--na:#C4BEDA;--na-bg:rgba(242,237,255,.07);--na-line:rgba(242,237,255,.24)}}
:root[data-theme="dark"]{
--bg:#0C0627;--surface:#120838;--raised:#160B40;--ink:#F2EDFF;--ink-soft:#D6CCF2;--muted:#BDB0DE;--dim:#A396C9;--faint:#9486BE;--accent:#BFA3FF;--on-accent:#12063A;
--line:rgba(242,237,255,.11);--line-soft:rgba(242,237,255,.065);--code:#0F0830;--tip-bg:#F2EDFF;--tip-ink:#170F2E;
--risk:#FF9F8E;--risk-bg:rgba(255,159,142,.12);--risk-line:rgba(255,159,142,.45);--unk:#F2C46D;--unk-bg:rgba(242,196,109,.11);--unk-line:rgba(242,196,109,.45);
--ok:#86D9AE;--ok-bg:rgba(134,217,174,.11);--ok-line:rgba(134,217,174,.42);--na:#C4BEDA;--na-bg:rgba(242,237,255,.07);--na-line:rgba(242,237,255,.24)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-underline-offset:2px}a:hover{color:var(--ink)}
p,li{overflow-wrap:anywhere}td{overflow-wrap:break-word}
h1,h2,h3,h4{margin:0}
.wrap{max-width:1180px;margin:0 auto;padding:32px 32px 64px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:.92em}
.dim{color:var(--dim)}.muted{color:var(--muted)}.strong{font-weight:600}.small{font-size:13px}.nowrap{white-space:nowrap}.ink{color:var(--ink)}
.ic{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round;flex:none}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 10px 3px 8px;border-radius:999px;font-size:12.5px;font-weight:600;line-height:1.35;border:1px solid;vertical-align:middle}
.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:6px;font-size:12.5px;font-weight:600;line-height:1.4;border:1px solid;white-space:nowrap;text-decoration:none}
.tag.mono{font-size:12px}
.c-risk{color:var(--risk);background:var(--risk-bg);border-color:var(--risk-line)}
.c-unk{color:var(--unk);background:var(--unk-bg);border-color:var(--unk-line)}
.c-ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-line)}
.c-na{color:var(--na);background:var(--na-bg);border-color:var(--na-line)}
.c-neutral{color:var(--muted);background:transparent;border-color:var(--line)}
a.c-clause,.c-clause{color:var(--on-accent);background:var(--accent);border-color:var(--accent)}
a.c-clause:hover{color:var(--on-accent);filter:brightness(1.1)}
.t-risk{color:var(--risk)}.t-unk{color:var(--unk)}.t-ok{color:var(--ok)}.t-na{color:var(--na)}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:14px}
.box{overflow-x:auto;-webkit-overflow-scrolling:touch}
.tbl{width:100%;border-collapse:collapse;font-size:13.5px}
.tbl th{text-align:left;font-size:12px;font-weight:600;color:var(--dim);padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:bottom}
.tbl td{padding:12px;border-bottom:1px solid var(--line-soft);vertical-align:top}
.tbl tbody:last-child tr:last-child td,.tbl tbody tr:last-child td{border-bottom:0}
.tbl .num{font-variant-numeric:tabular-nums;text-align:right}
.tbl td.mono{font-size:12.5px}
.tbl.inner{font-size:13px}.tbl.inner td{padding:8px 10px}.tbl.inner th{padding:8px 10px}
.note{display:block;font-size:12px;line-height:1.45;color:var(--dim);margin-top:3px;font-weight:400}
.note.assume{font-style:italic}.note.link{overflow-wrap:anywhere}.note.ink{color:var(--ink);font-size:13px;margin-top:6px}
/* first screen */
.top{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px 16px}
h1{font-size:17px;font-weight:700;letter-spacing:-.01em}
h1 a{color:inherit;text-decoration:underline;text-decoration-color:var(--line);text-underline-offset:4px}
.printbtns{display:none;gap:8px}
.js .printbtns{display:flex}
.printbtns button{font:inherit;font-size:13px;font-weight:600;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:7px 12px;cursor:pointer;min-height:36px}
.printbtns button:hover{border-color:var(--accent)}
.printbtns button:focus-visible,.info:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.headline{margin:18px 0 0;font-size:24px;line-height:1.35;font-weight:650;letter-spacing:-.015em;max-width:900px}
.banner{margin-top:14px;padding:12px 14px;border-radius:10px;background:var(--unk-bg);border:1px solid var(--unk-line);color:var(--ink)}
.cards{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-top:22px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px;display:flex;flex-direction:column;gap:8px}
.card.b-risk{border-color:var(--risk-line)}.card.b-unk{border-color:var(--unk-line)}
.cnum{font-size:36px;line-height:1;font-weight:700;font-variant-numeric:tabular-nums}
.cnum.sm{font-size:30px}
.clabel{display:flex;align-items:center;gap:6px;font-size:13px;font-weight:600}
.compcard{background:var(--raised)}
.segs{display:flex;gap:3px}
.seg{height:8px;border-radius:2px;flex-basis:0;min-width:3px}
.s-risk{background:var(--risk)}.s-unk{background:var(--unk)}.s-ok{background:var(--ok)}.s-na{background:var(--na-line)}
.legacyline{display:flex;flex-wrap:wrap;align-items:center;gap:8px 20px;margin:12px 0 0;font-size:13px;color:var(--muted)}
.lline{display:inline-flex;align-items:center;gap:8px;color:var(--muted);text-decoration:none}a.lline:hover{color:var(--accent)}
.scope{margin:12px 0 0;padding:8px 12px;background:var(--raised);border-radius:10px;font-size:13px;color:var(--ink-soft);max-width:900px}
.scope strong{color:var(--ink)}
.csub{font-size:11.5px;line-height:1.35;color:var(--dim)}
.flag{margin-top:4px;font-size:11px;padding:1px 6px}
.implies{margin:0;padding:10px 12px;border:1px solid var(--unk-line);border-radius:10px;background:var(--unk-bg);color:var(--ink);font-size:13px}
.block{margin-top:36px;display:flex;flex-direction:column;gap:12px}
.sechead{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.sechead h2{font-size:20px;letter-spacing:-.01em}
.hint{margin:0;font-size:13px;color:var(--muted)}
.legend{margin:0;font-size:12px;color:var(--dim)}
.empty{margin:0;color:var(--dim);font-size:13.5px}
/* info tooltips: hover, tap (focus) and keyboard focus, no script */
.info{position:relative;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;margin:-4px 0;border-radius:50%;color:var(--dim);cursor:help;font-size:14px;font-weight:400;vertical-align:middle;text-transform:none;letter-spacing:0}
.info:hover,.info:focus{color:var(--accent)}
.info .tip{position:absolute;left:50%;top:calc(100% + 6px);transform:translateX(-50%);z-index:20;width:max-content;max-width:300px;padding:10px 12px;border-radius:10px;background:var(--tip-bg);color:var(--tip-ink);font-size:12.5px;line-height:1.45;font-weight:400;text-align:left;white-space:normal;box-shadow:0 6px 24px rgba(0,0,0,.25);display:none}
.info:hover .tip,.info:focus .tip,.info:focus-within .tip{display:block}
.info .tip strong{font-weight:700}
/* priority table */
.priority{min-width:1000px}
.priority tbody.asset+tbody.asset tr:first-child td{border-top:1px solid var(--line)}
.priority tbody.asset tr:first-child td{border-bottom:0;padding-bottom:4px}
.row-risk td{background:var(--risk-bg)}
.margin{min-width:130px}
.mrow{display:flex;align-items:center;gap:10px}
.mval{font-weight:700;min-width:42px;text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.track{position:relative;display:block;width:64px;height:8px;border-radius:4px;background:var(--line-soft);flex:none}
.track.empty{border:1px dashed var(--unk-line)}
.zero{position:absolute;left:50%;top:-3px;bottom:-3px;width:1px;background:var(--faint)}
.fill{position:absolute;top:0;bottom:0;border-radius:4px}
.ext{position:absolute;top:3px;height:0;border-top:2px dashed var(--risk)}
.margin .note.mono{white-space:nowrap}
.f-at_risk{background:var(--risk)}.f-not_at_risk{background:var(--ok)}.f-mitigated_pq_clients{background:var(--ok);opacity:.55}.f-unknown{background:var(--unk)}
.chip{white-space:nowrap}
.action{font-size:13px;color:var(--ink-soft);min-width:240px}
.more{font-size:12px;color:var(--dim);white-space:nowrap}
.rowdetail td{padding-top:0;padding-bottom:10px}
.rowdetail summary{cursor:pointer;list-style:none;display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--accent);padding:2px 0}
.rowdetail summary::-webkit-details-marker{display:none}
.rowdetail details[open] summary{margin-bottom:8px}
.chev{transition:transform .15s}
details[open]>summary .chev{transform:rotate(90deg)}
.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 24px;margin-bottom:10px}
.facts dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;margin:0;font-size:13px;align-content:start}
.facts dt{color:var(--dim);font-weight:600}.facts dd{margin:0}
/* completeness and lists */
.counts{display:flex;flex-wrap:wrap;gap:10px 22px}
.counts a{white-space:nowrap}
.counts a{display:flex;align-items:center;gap:8px;text-decoration:none;color:var(--ink);font-size:13.5px}
.counts a:hover{color:var(--accent)}
.lists{display:flex;flex-direction:column;gap:8px}
.ev{background:var(--surface);border:1px solid var(--line);border-radius:12px}
.ev>summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px;padding:12px 16px;font-weight:600;font-size:14px}
.ev>summary::-webkit-details-marker{display:none}
.ev>summary .chev{color:var(--dim)}
.ev>summary .meta{margin-left:auto;font-weight:400;font-size:12.5px;color:var(--dim);text-align:right}
.evbody{padding:0 16px 14px;display:flex;flex-direction:column;gap:10px}
.evbody>p{font-size:13.5px;color:var(--muted);margin:0}
.evbody ul{margin:0;padding-left:18px;font-size:13.5px;color:var(--muted)}
.sub{margin:6px 0 0;font-size:13px}
ul.limits{list-style:none;padding:0}
.limits li{display:flex;gap:10px;align-items:baseline;margin:6px 0}
.coverage td:first-child{min-width:200px}
.cl{display:inline-flex;align-items:center;gap:8px}
.ar{font-family:"Geeza Pro","Noto Sans Arabic","SF Arabic","Segoe UI",Tahoma,sans-serif;color:var(--accent);font-weight:600;font-size:14px}
.coverage .info{margin-left:4px}
.values{min-width:720px}.values td:first-child{width:260px}
th.area{width:120px}th.offer{width:200px}
.tbl.inner{min-width:720px}
.probes{gap:12px}
.cmd{margin:0;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px 14px;white-space:pre-wrap;word-break:break-word;color:var(--ink-soft)}
.circular{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;margin:0;font-size:13.5px;color:var(--muted)}
.circular dt{color:var(--ink);font-weight:600}.circular dd{margin:0}
.leadline{margin:4px 0 0;font-weight:600;color:var(--ink)}
.clausetext{border-top:1px solid var(--line-soft);padding-top:12px;display:flex;flex-direction:column;gap:10px}
.clausetext h3{font-size:15px;display:flex;align-items:center;gap:8px}
.clausetext h4{font-size:13px;margin-bottom:4px}
.quote{margin:0;border-radius:10px;background:var(--raised);padding:12px 14px;color:var(--ink-soft);font-size:14px}
.quote p{margin:0}.quote ul{margin:8px 0 0;padding-left:18px}
.two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.gloss{display:grid;grid-template-columns:max-content 1fr;gap:8px 16px;margin:0;font-size:13.5px}
.gi{display:contents}
.gloss dt{font-weight:600}.gloss dd{margin:0;color:var(--muted)}
@media (max-width:1000px){.cards{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:640px){.wrap{padding:20px 16px 48px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.two,.facts{grid-template-columns:1fr}
.headline{font-size:20px}.circular,.gloss{grid-template-columns:1fr}.ev>summary .meta{display:none}.info .tip{max-width:240px}}
@page{size:A4;margin:14mm 13mm 18mm;@top-left{content:none}@top-center{content:none}@top-right{content:none}@bottom-center{content:none}
@bottom-right{content:"Page " counter(page) " of " counter(pages);font:8.5pt -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;color:#575073}}
@media print{
:root,:root:not([data-theme="light"]),:root[data-theme="dark"]{color-scheme:light;
--bg:#FFFFFF;--surface:#FFFFFF;--raised:#F6F4FB;--ink:#170F2E;--ink-soft:#2C2349;--muted:#463D63;--dim:#575073;--faint:#625A82;--accent:#5537BD;--on-accent:#FFFFFF;
--line:rgba(23,15,46,.18);--line-soft:rgba(23,15,46,.1);--code:#F6F4FB;
--risk:#B42318;--risk-bg:#FDECEA;--risk-line:#F1B1A9;--unk:#8A5300;--unk-bg:#FFF3DC;--unk-line:#E8BE74;
--ok:#1E6B45;--ok-bg:#E6F4EC;--ok-line:#9BCFB1;--na:#4E4A5E;--na-bg:#EDECF1;--na-line:#C6C2D2}
body{font-size:10pt;background:#fff}
.wrap{max-width:none;padding:0}
.printbtns,.info{display:none !important}
.headline{font-size:15pt;margin-top:8pt}
.cards{grid-template-columns:repeat(6,minmax(0,1fr));gap:6px;margin-top:12pt}.card{padding:8px 10px}.cnum{font-size:20pt}.cnum.sm{font-size:16pt}.clabel{font-size:9pt}
.block{margin-top:16pt}
.tbl{font-size:9pt}.tbl th{font-size:8pt;padding:5px 6px}.tbl td{padding:5px 6px}.note{font-size:8pt}
.priority,.values,.tbl.inner{min-width:0}.action{min-width:0;font-size:8.5pt}.margin{min-width:0}.track{width:44px}
.box{overflow:visible}
.tbl thead{display:table-header-group}
.tbl thead{display:table-header-group}
.tbl tr,.priority tbody.asset,.gi,.limits li,.clausetext .quote,.facts dl>*,.implies,.scope,#completeness>.hint{break-inside:avoid}
p,li{orphans:2;widows:2}
h2,h3,h4,.sechead,.ev>summary,.sub,.hint,.clausetext h3{break-after:avoid}
/* flex and grid containers do not fragment cleanly: plain block layout in print */
.block,.lists,.evbody,.clausetext,.facts,.probes{display:block}
.block>*+*,.lists>*+*,.evbody>*+*,.clausetext>*+*,.probes>*+*{margin-top:8pt}
.gloss,.circular,.facts dl{display:block}
.gi{display:block;margin:0 0 6pt}
.gloss dt,.circular dt,.facts dt{display:block}.gloss dd,.circular dd,.facts dd{margin:0 0 4pt}
.facts dl+dl{margin-top:6pt}
.two{display:block}.two>*+*{margin-top:6pt}
.card,.panel,.ev{break-inside:auto;-webkit-box-decoration-break:clone;box-decoration-break:clone}
.counts{flex-wrap:nowrap;gap:4px 12px}.counts a{font-size:9pt;gap:5px}.counts .chip{padding:1px 7px 1px 5px}
.clabel{white-space:nowrap;font-size:8.5pt}
/* a priority row stays with the start of its details; long details continue on the next page */
.print-full .priority tbody.asset,.priority tr.rowdetail{break-inside:auto}
.priority tbody.asset>tr:first-child{break-inside:avoid;break-after:avoid}
.rowdetail summary{break-after:avoid}
.facts{columns:2;column-gap:18pt}
.facts dl{display:block}
.facts dl>dt{float:left;clear:left;width:7.5em}
.facts dl>dd{margin:0 0 3pt 8em;break-inside:avoid}
.chip,.tag,.seg,.fill,.track,.row-risk td,.c-clause{-webkit-print-color-adjust:exact;print-color-adjust:exact}
a{color:inherit;text-decoration:none}
/* summary print (the default, and without script): first screen, completeness, clause coverage */
html:not(.print-full) .rowdetail,html:not(.print-full) .lists,html:not(.print-full) #appendix{display:none}
/* full print: everything opened by the script */
#probes .tbl{table-layout:fixed}#probes th.offer{width:22%}#probes th:nth-child(2){width:11%}#probes th:nth-child(3){width:34%}
#probes td.mono{word-break:break-all}
.print-full .ev{break-inside:auto}
.print-full details::details-content{content-visibility:visible}
.print-full .ev>summary .chev,.print-full .rowdetail summary .chev{display:none}
}
`
