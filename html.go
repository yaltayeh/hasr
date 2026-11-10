package main

import (
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"
)

// clauseInfo is one section of the report. Text and Items quote the author's
// unofficial English translation verbatim (DECISIONS.md, "Clause text"); the
// official text is the Arabic circular. Title, Provides and Institution are
// Hasr's own wording. PROVISIONAL wording, for the author's review.
type clauseInfo struct {
	N           int
	Title       string
	Due         string
	Text        string   // unofficial translation, verbatim
	Items       []string // Clause 2's sub-items, verbatim
	Provides    []string
	Institution []string
}

var clauses = []clauseInfo{
	{
		N: 1, Title: "Enterprise quantum-risk assessment", Due: "End of Q1 2027",
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
		N: 2, Title: "Inventory and classification of cryptographic assets", Due: "End of Q4 2026",
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
		N: 3, Title: "Plans to reach the required crypto-agility", Due: "No date in the circular",
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
		N: 4, Title: "Standing monitoring by committees", Due: "No date in the circular",
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

type htmlView struct {
	RiskReport
	Circular struct{ Title, Lead, Distribution string }
	Clauses  []clauseInfo
	Counts   map[string]int
	CSS      template.CSS
}

func writeHTML(w io.Writer, r RiskReport) error {
	v := htmlView{RiskReport: r, Circular: circular, Clauses: clauses, Counts: map[string]int{}, CSS: template.CSS(reportCSS)}
	for _, a := range r.Assets {
		v.Counts[a.Mosca.Status]++
	}
	for _, list := range [][]Asset{r.Assets, r.NeedsOwnerInput, r.NotAssessed} {
		for _, a := range list {
			if a.Legacy == "yes" {
				v.Counts["legacy"]++
			}
		}
	}
	return reportTemplate.Execute(w, v)
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"years": func(v *float64) string {
		if v == nil {
			return "—"
		}
		return num(*v)
	},
	"signed": func(v *float64) string {
		switch {
		case v == nil:
			return "—"
		case *v > 0:
			return "+" + num(*v)
		case *v < 0:
			return "−" + num(-*v)
		}
		return "0"
	},
	"src": func(s Sourced) string {
		if s.Years == nil {
			return "not set"
		}
		return s.Source
	},
	"status": func(s string) string {
		return map[string]string{
			statusAtRisk: "At risk", statusNotAtRisk: "Not at risk",
			statusMitigated: "Mitigated for PQ-capable clients", statusUnknown: "Unknown",
		}[s]
	},
	"cap":                func(s string) string { return sentenceCase(s) },
	"disagreementCauses": func() string { return disagreementCauses },
	"join":               strings.Join,
	"versions":           shortVersions,
	"short":              shortRef,
	"key":                func(pk PublicKey) string { return pk.keyLabel() },
	"when":               func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"day":                func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"dash":               dash,
	"inc":                func(i int) int { return i + 1 },
	"slice3":             func(a, b, c []Asset) [][]Asset { return [][]Asset{a, b, c} },
	"anyFindings": func(as []Asset) bool {
		for _, a := range as {
			if len(a.Findings) > 0 {
				return true
			}
		}
		return false
	},
}).Parse(reportHTML))

// num prints a number of years without float noise: 4.15, 10, 0.5.
func num(v float64) string { return strconv.FormatFloat(round2(v), 'f', -1, 64) }

func sentenceCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

const reportHTML = `{{define "links"}}{{range .}}<div class="sub link"><a href="{{.}}" rel="noopener noreferrer">{{.}}</a></div>{{end}}{{end}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hasr quantum-readiness report</title>
<style>{{.CSS}}</style>
</head>
<body>
<main>
<header class="top">
  <p class="eyebrow">Hasr · Quantum-readiness report</p>
  <h1>Cryptographic inventory against SAMA Circular No. 482021280</h1>
  <p class="meta">Report generated {{when .GeneratedAt}} · Scan run {{when .Inputs.ScanGeneratedAt}}</p>
  <dl class="circular">
    <dt>Circular</dt><dd>SAMA Circular No. 482021280, dated 1448/03/14 H (27 August 2026): <strong>{{.Circular.Title}}</strong></dd>
    <dt>Distribution</dt><dd>{{.Circular.Distribution}}</dd>
  </dl>
  <p class="fineprint">The circular's title, distribution and clause texts are quoted from the author's unofficial English translation; the official text is the Arabic circular. The labels "Clause 1–4" and "2a/2b" are Hasr's; the circular numbers its clauses First to Fourth and does not number Clause 2's two items.</p>
  {{if .MissingValues}}<div class="banner"><strong>Mosca values not set:</strong> {{join .MissingValues "; "}}. Until they are provided, the at-risk status is "Unknown" wherever a missing value is needed.</div>{{end}}
</header>

<section class="cards" aria-label="Overview">
  <div class="card"><span class="num">{{.Completeness.Assessed}}<small> of {{.Completeness.Known}}</small></span><span class="lbl">{{if .Completeness.CloudDiscovered}}known targets assessed (mapped, plus found in the cloud){{else}}mapped targets assessed{{end}}</span></div>
  <div class="card risk"><span class="num">{{index .Counts "at_risk"}}</span><span class="lbl">at risk</span></div>
  <div class="card unknown"><span class="num">{{index .Counts "unknown"}}</span><span class="lbl">unknown priority</span></div>
  <div class="card ok"><span class="num">{{index .Counts "mitigated_pq_clients"}}</span><span class="lbl">mitigated for PQ-capable clients</span></div>
  <div class="card ok"><span class="num">{{index .Counts "not_at_risk"}}</span><span class="lbl">not at risk</span></div>
  <div class="card warn"><span class="num">{{index .Counts "legacy"}}</span><span class="lbl">targets accepting legacy protocols or weak suites</span></div>
</section>

<nav class="toc" aria-label="Contents">
  {{range .Clauses}}<a href="#clause-{{.N}}">Clause {{.N}}</a>{{end}}<a href="#appendix">Appendix</a>
</nav>

<blockquote class="quote lead">
  <p>{{.Circular.Lead}}</p>
  <cite>Unofficial translation by the author</cite>
</blockquote>

{{range $c := .Clauses}}
<section class="clause" id="clause-{{$c.N}}">
  <div class="clause-head">
    <h2>Clause {{$c.N}} <span class="label">(unofficial translation)</span> <span class="title">{{$c.Title}}</span></h2>
    <span class="due">Due: {{$c.Due}}</span>
  </div>
  <blockquote class="quote">
    <p>{{$c.Text}}</p>
    {{if $c.Items}}<ul>{{range $c.Items}}<li>{{.}}</li>{{end}}</ul>{{end}}
    <cite>Unofficial translation by the author</cite>
  </blockquote>
  <div class="split">
    <div><h3>What Hasr provides</h3><ul>{{range $c.Provides}}<li>{{.}}</li>{{end}}</ul></div>
    <div><h3>What the institution still has to do</h3><ul>{{range $c.Institution}}<li>{{.}}</li>{{end}}</ul></div>
  </div>

  {{if eq $c.N 1}}
  <p>The technical input is the priority table under Clause 2a and the findings under Clause 3.</p>
  {{end}}

  {{if eq $c.N 2}}
  <h3 id="clause-2a">2a · Systems, data and migration priority</h3>
  <p class="hint">Mosca's inequality: an asset is at risk when X + Y &gt; Z. X: years the data must stay confidential. Y: years to migrate. Z: the time until the quantum threat or a regulatory deadline, in years. Sorted: at risk (largest margin first), unknown, not at risk, mitigated.</p>
  {{if $.Assets}}
  <div class="scroll"><table>
    <thead><tr><th>#</th><th>Target</th><th>System · service</th><th>Owner</th><th>Classification</th><th>Key exchange</th><th>Legacy</th><th class="n">X</th><th class="n">Y</th><th class="n">Z</th><th class="n">X+Y−Z</th><th>Status</th></tr></thead>
    <tbody>
    {{range $i, $a := $.Assets}}
      <tr>
        <td>{{inc $i}}</td>
        <td class="mono">{{$a.Target}}{{range $a.Cloud}}<div class="sub">{{.Provider}}: {{.Name}} ({{.Match}} match)</div>{{end}}</td>
        <td>{{$a.Mapping.System}}{{with index $a.FieldSources "system"}}<div class="sub">from {{.}}</div>{{end}}<div class="sub">{{$a.Mapping.Service}}</div>{{with index $a.FieldSources "service"}}<div class="sub">from {{.}}</div>{{end}}</td>
        <td>{{dash $a.Mapping.Owner}}{{with index $a.FieldSources "owner"}}<div class="sub">from {{.}}</div>{{end}}</td>
        <td>{{dash $a.Mapping.DataClassification}}</td>
        <td><span class="tag kex-{{$a.KeyExchange}}">{{$a.KeyExchange}}</span></td>
        <td><span class="tag legacy-{{$a.Legacy}}">{{$a.Legacy}}</span></td>
        <td class="n">{{years $a.Mosca.X}}<div class="sub">{{$a.Mosca.XSource}}</div></td>
        <td class="n">{{years $a.Mosca.Y}}<div class="sub">{{$a.Mosca.YSource}}</div>{{if $a.Mosca.YAssumption}}<div class="sub assume">assumption; override per entry</div>{{end}}</td>
        <td class="n">{{years $a.Mosca.Z}}</td>
        <td class="n strong">{{signed $a.Mosca.Margin}}{{if $a.Mosca.MarginScope}}<div class="sub scope">({{$a.Mosca.MarginScope}})</div>{{end}}</td>
        <td><span class="badge s-{{$a.Mosca.Status}}">{{status $a.Mosca.Status}}</span>{{range $a.Mosca.Notes}}<div class="sub">{{.}}</div>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table></div>
  {{else}}<p class="empty">No mapped target was fully assessed.</p>{{end}}

  <h4 id="values">Values used, with their sources</h4>
  <p class="hint">From <span class="mono">{{$.Inputs.PolicyFile}}</span>. A value given per entry in the mapping file replaces the default for that entry.</p>
  <div class="scroll"><table class="plain values">
    <thead><tr><th>Value</th><th class="n">Years</th><th>Source</th></tr></thead>
    <tbody>
      <tr><td>Z: the time until the quantum threat or a regulatory deadline</td><td class="n">{{years $.Policy.Z.Years}}{{if $.Policy.Z.Date}}<div class="sub">until {{$.Policy.Z.Date}}</div>{{end}}</td><td>{{if $.Policy.Z.Years}}{{$.Policy.Z.Source}}{{template "links" $.Policy.Z.Links}}{{else}}not set{{end}}</td></tr>
      {{range $.Policy.ClassificationLevels}}<tr><td>Default X: {{.Label}}</td><td class="n">{{years .ShelfLife.Years}}</td><td>{{src .ShelfLife}}{{template "links" .ShelfLife.Links}}</td></tr>{{end}}
      {{with $.Policy.MigrationYearsDefault}}
      <tr><td>Default Y: already hybrid</td><td class="n">{{years .AlreadyHybrid.Years}}</td><td>{{src .AlreadyHybrid}}{{template "links" .AlreadyHybrid.Links}}{{if .AlreadyHybrid.Assumption}}<div class="sub assume">assumption; override per entry</div>{{end}}</td></tr>
      <tr><td>Default Y: TLS 1.3, classical key exchange</td><td class="n">{{years .TLS13Classical.Years}}</td><td>{{src .TLS13Classical}}{{template "links" .TLS13Classical.Links}}{{if .TLS13Classical.Assumption}}<div class="sub assume">assumption; override per entry</div>{{end}}</td></tr>
      <tr><td>Default Y: no TLS 1.3</td><td class="n">{{years .NoTLS13.Years}}</td><td>{{src .NoTLS13}}{{template "links" .NoTLS13.Links}}{{if .NoTLS13.Assumption}}<div class="sub assume">assumption; override per entry</div>{{end}}</td></tr>
      <tr><td>Default Y: managed TLS policy (cloud)</td><td class="n">{{years .ManagedTLSPolicy.Years}}</td><td>{{src .ManagedTLSPolicy}}{{template "links" .ManagedTLSPolicy.Links}}{{if .ManagedTLSPolicy.Assumption}}<div class="sub assume">assumption; override per entry</div>{{end}}</td></tr>
      {{end}}
    </tbody>
  </table></div>
  <p class="hint">Default Y applies only to endpoints whose third_party is "in-house"; a vendor's timeline is never guessed.</p>

  <h3 id="clause-2b">2b · Crypto-agility evidence, constraints and third parties</h3>
  <p class="hint">Hasr's crypto-agility rating is planned and not in this version. The evidence below is what the scan{{if $.Inputs.Cloud}} and the cloud records{{end}} show today.</p>
  {{if $.Assets}}
  <div class="scroll"><table>
    <thead><tr><th>Target</th><th>System</th><th>Third party</th><th>Constraints</th><th>TLS versions</th><th>Key-exchange evidence</th>{{if $.Inputs.Cloud}}<th>Cloud evidence</th>{{end}}</tr></thead>
    <tbody>
    {{range $.Assets}}
      <tr>
        <td class="mono">{{.Target}}</td>
        <td>{{.Mapping.System}}</td>
        <td>{{dash .Mapping.ThirdParty}}</td>
        <td>{{dash .Mapping.Constraints}}</td>
        <td>{{versions .VersionsAccepted}}</td>
        <td>{{range .Findings}}{{if eq .Area "key_exchange"}}<div>{{.Finding}}</div>{{end}}{{end}}</td>
        {{if $.Inputs.Cloud}}<td>{{range .Agility}}<div>{{.}}</div>{{else}}—{{end}}</td>{{end}}
      </tr>
    {{end}}
    </tbody>
  </table></div>
  {{end}}

  <h3>Certificates</h3>
  <p class="hint">Listed with their algorithms. No Mosca priority for certificates in this version.</p>
  <div class="scroll"><table>
    <thead><tr><th>Target</th><th>Certificate</th><th>Key</th><th>Signature</th><th>Chain</th><th>Hostname</th><th>Validity</th><th>Not after</th><th>Issuer</th></tr></thead>
    <tbody>
    {{range $list := (slice3 $.Assets $.NeedsOwnerInput $.NotAssessed)}}{{range $a := $list}}{{range $c := $a.Certificates}}
      <tr>
        <td class="mono">{{$a.Target}}</td>
        <td class="mono">{{short $c.Ref}}</td>
        <td>{{key $c.PublicKey}}</td>
        <td>{{$c.SignatureAlgorithm}}</td>
        <td>{{if $c.Verification.ChainTrusted}}trusted{{else}}<span class="warn-text">not trusted</span>{{end}}</td>
        <td>{{$c.Verification.HostnameMatch}}</td>
        <td>{{$c.Verification.Validity}}</td>
        <td>{{day $c.NotAfter}}</td>
        <td>{{$c.Issuer}}</td>
      </tr>
    {{end}}{{end}}{{end}}
    </tbody>
  </table></div>

  <h3 id="completeness">Completeness of the inventory procedure</h3>
  <div class="figure">
    <span class="big">{{$.Completeness.Assessed}} of {{$.Completeness.Known}}</span>
    <span>{{if $.Completeness.CloudDiscovered}}known targets ({{$.Completeness.Mapped}} mapped, plus {{$.Completeness.CloudDiscovered}} found in the cloud and not in the target list){{else}}mapped targets{{end}} were scanned and fully assessed.</span>
  </div>
  <ul class="counts">
    <li><a href="#needs-owner-input">Needs owner input</a>: {{$.Completeness.NeedsOwnerInput}} scanned, not in the mapping file</li>
    <li><a href="#mapped-not-scanned">Mapped but not scanned</a>: {{$.Completeness.MappedNotScanned}}</li>
    <li><a href="#not-assessed">Not assessed</a>: {{$.Completeness.NotAssessed}} unreachable or incomplete</li>
    <li><a href="#not-tested">Not tested</a>: {{len $.NotTested}} stated scanner limits</li>
    {{if $.Inputs.Cloud}}<li><a href="#cloud-discovered">Found in the cloud, not in the target list</a>: {{$.Completeness.CloudDiscovered}}</li>
    <li><a href="#disagreements">Scan and cloud records disagree</a>: {{len $.Disagreements}}</li>
    <li><a href="#cloud-limits">Not read</a>: {{len $.CloudLimits}} stated limits of the cloud collectors</li>{{end}}
  </ul>

  <h4 id="needs-owner-input">Needs owner input</h4>
  {{if $.NeedsOwnerInput}}
  <p class="hint">Scanned but not in the mapping file: no owner, classification or priority. Priority: unknown.</p>
  <div class="scroll"><table>
    <thead><tr><th>Target</th><th>Key exchange</th><th>Legacy</th><th>TLS versions</th><th>Findings</th></tr></thead>
    <tbody>
    {{range $.NeedsOwnerInput}}
      <tr><td class="mono">{{.Target}}</td><td><span class="tag kex-{{.KeyExchange}}">{{.KeyExchange}}</span></td><td><span class="tag legacy-{{.Legacy}}">{{.Legacy}}</span></td><td>{{versions .VersionsAccepted}}</td><td>{{len .Findings}} (see Clause 3){{if .Problem}}<div class="sub">{{.Problem}}</div>{{end}}</td></tr>
    {{end}}
    </tbody>
  </table></div>
  {{else}}<p class="empty">None.</p>{{end}}

  <h4 id="mapped-not-scanned">Mapped but not scanned</h4>
  {{if $.MappedNotScanned}}
  <div class="scroll"><table>
    <thead><tr><th>Target</th><th>System</th><th>Service</th><th>Owner</th></tr></thead>
    <tbody>{{range $.MappedNotScanned}}<tr><td class="mono">{{.Target}}</td><td>{{.System}}</td><td>{{.Service}}</td><td>{{.Owner}}</td></tr>{{end}}</tbody>
  </table></div>
  {{else}}<p class="empty">None.</p>{{end}}

  <h4 id="not-assessed">Not assessed</h4>
  {{if $.NotAssessed}}
  <p class="hint">Mapped and scanned, but unreachable or incomplete. Never treated as low priority.</p>
  <div class="scroll"><table>
    <thead><tr><th>Target</th><th>System</th><th>Owner</th><th>Problem</th></tr></thead>
    <tbody>{{range $.NotAssessed}}<tr><td class="mono">{{.Target}}</td><td>{{.Mapping.System}}</td><td>{{.Mapping.Owner}}</td><td>{{.Problem}}</td></tr>{{end}}</tbody>
  </table></div>
  {{else}}<p class="empty">None.</p>{{end}}

  <h4 id="not-tested">Not tested: the scanner's stated limits</h4>
  <ul class="limits">{{range $.NotTested}}<li><span class="mono">{{.ID}}</span>: {{.Detail}}</li>{{end}}</ul>

  {{if $.Inputs.Cloud}}
  <h4 id="cloud-discovered">Found in the cloud, not in the target list</h4>
  {{if $.CloudDiscovered}}
  <p class="hint">Endpoints the cloud records list that no scanned or mapped target matched. Hasr never scans them automatically: review them and add the ones in scope to the mapping file.</p>
  <div class="scroll"><table>
    <thead><tr><th>Provider · scope</th><th>Name</th><th>Hostnames</th><th>Port</th><th>Protocol</th><th>Exposure</th><th>Key exchange</th><th>Legacy</th><th>Policy</th></tr></thead>
    <tbody>{{range $.CloudDiscovered}}<tr><td>{{.Provider}} · {{.Scope}}</td><td>{{.Name}}</td><td class="mono">{{join .Hostnames ", "}}</td><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Exposure}}</td>
      {{if .TLS}}<td><span class="tag kex-{{.TLS.KeyExchange}}">{{.TLS.KeyExchange}}</span></td><td><span class="tag legacy-{{.TLS.Legacy}}">{{.TLS.Legacy}}</span></td><td>{{.TLS.Policy.Name}}</td>{{else}}<td colspan="3">{{range .Notes}}<div class="sub">{{.}}</div>{{end}}</td>{{end}}</tr>{{end}}</tbody>
  </table></div>
  {{else}}<p class="empty">None.</p>{{end}}

  <h4 id="disagreements">Scan and cloud records disagree</h4>
  {{if $.Disagreements}}
  <p class="hint">Possible causes: {{disagreementCauses}}. The worse of the two values counts for priority.</p>
  <div class="scroll"><table>
    <thead><tr><th>Target</th><th>Cloud record</th><th>Field</th><th>Scan saw</th><th>Cloud record says</th><th>Counted</th></tr></thead>
    <tbody>{{range $.Disagreements}}<tr><td class="mono">{{.Target}}</td><td>{{.Provider}} {{.Name}}</td><td>{{.Field}}</td><td>{{.Scan}}</td><td>{{.Cloud}}</td><td>{{.Counted}}</td></tr>{{end}}</tbody>
  </table></div>
  {{else}}<p class="empty">None.</p>{{end}}

  <h4 id="cloud-limits">Not read: the cloud collectors' stated limits</h4>
  <ul class="limits">{{range $.CloudLimits}}<li><span class="mono">{{.ID}}</span>: {{.Detail}}</li>{{end}}</ul>
  {{end}}
  {{end}}

  {{if eq $c.N 3}}
  <h3>Recommended actions</h3>
  {{if anyFindings $.Assets}}
  {{range $i, $a := $.Assets}}{{if $a.Findings}}
  <div class="actions">
    <h4><span class="rank">{{inc $i}}</span> <span class="mono">{{$a.Target}}</span> · {{$a.Mapping.System}} <span class="badge s-{{$a.Mosca.Status}}">{{status $a.Mosca.Status}}</span></h4>
    <div class="scroll"><table class="plain"><thead><tr><th>Area</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>
    {{range $a.Findings}}<tr><td>{{.Area}}</td><td>{{.Finding}}</td><td>{{.Action}}</td></tr>{{end}}
    </tbody></table></div>
  </div>
  {{end}}{{end}}
  {{else}}<p class="empty">No findings on assessed assets.</p>{{end}}
  {{if anyFindings $.NeedsOwnerInput}}
  <h3>Also found on targets that need owner input (priority unknown)</h3>
  {{range $a := $.NeedsOwnerInput}}{{if $a.Findings}}
  <div class="actions">
    <h4><span class="mono">{{$a.Target}}</span> <span class="badge s-unknown">Unknown</span></h4>
    <div class="scroll"><table class="plain"><thead><tr><th>Area</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>
    {{range $a.Findings}}<tr><td>{{.Area}}</td><td>{{.Finding}}</td><td>{{.Action}}</td></tr>{{end}}
    </tbody></table></div>
  </div>
  {{end}}{{end}}
  {{end}}
  {{end}}

  {{if eq $c.N 4}}
  <h3>How this report is reproduced</h3>
  <pre class="cmd">hasr scan [--targets {{$.Inputs.MappingFile}}] [host:port ...] &gt; scan.json
{{range $.Inputs.Cloud}}collectors/{{.Provider}}/collect.sh -o RAW_DIR --region REGION ...
hasr cloud {{.Provider}} --from RAW_DIR &gt; {{.File}}
{{end}}hasr report --scan scan.json --map {{$.Inputs.MappingFile}}{{range $.Inputs.Cloud}} --cloud {{.File}}{{end}} --policy {{$.Inputs.PolicyFile}}</pre>
  <p>This report was built from <span class="mono">{{$.Inputs.ScanFile}}</span> (scan run {{when $.Inputs.ScanGeneratedAt}}, scan schema {{$.Inputs.ScanSchemaVersion}}) and <span class="mono">{{$.Inputs.MappingFile}}</span>. Keep each scan's JSON with the report as evidence. Tracking changes between scans is planned.</p>
  {{end}}
</section>
{{end}}

<section class="clause" id="appendix">
  <h2>Appendix</h2>
  <h3>Inputs</h3>
  <ul>
    <li>Scan: <span class="mono">{{.Inputs.ScanFile}}</span>, {{.Completeness.Scanned}} targets, {{.Inputs.ScanTool.Name}} with {{.Inputs.ScanTool.Go}}</li>
    <li>Mapping: <span class="mono">{{.Inputs.MappingFile}}</span>, {{.Completeness.Mapped}} rows</li>
    <li>Policy: <span class="mono">{{.Inputs.PolicyFile}}</span> (classification levels: {{range $i, $l := .Policy.ClassificationLevels}}{{if $i}}, {{end}}{{$l.Label}}{{end}})</li>
    {{range .Inputs.Cloud}}<li>Cloud: <span class="mono">{{.File}}</span>, provider {{.Provider}}, collected {{when .CollectedAt}}; scopes: {{range $i, $s := .Scopes}}{{if $i}}, {{end}}{{$s.Scope}} ({{$s.Status}}){{end}}</li>{{end}}
  </ul>
  <h3>Method</h3>
  <p>Each target receives a fixed set of ordinary TLS handshakes, each with a different offer: the default offer; hybrid key exchange only; classical key exchange only; TLS 1.2 at most; TLS 1.1 only; TLS 1.0 only; TLS 1.2 with weak suites only. Nothing beyond a handshake is sent, and only targets the institution owns or is authorised to assess may be scanned.</p>
</section>

<footer>Generated by Hasr ({{.Tool.Go}}) · report schema {{.SchemaVersion}}</footer>
</main>
</body>
</html>
`

const reportCSS = `
:root{--bg:#f7f7f5;--paper:#fff;--ink:#1c1d1f;--muted:#5d6168;--line:#e2e3e0;--accent:#1f5f4a;
--risk:#b42318;--risk-bg:#fdecea;--warn:#9a5b00;--warn-bg:#fff4e0;--ok:#1f6b45;--ok-bg:#e7f4ec;--unk:#6b5a00;--unk-bg:#fbf6d9;--code:#f1f1ee}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#131416;--paper:#1b1c1f;--ink:#e8e8e6;--muted:#a3a6ad;--line:#2d2f33;--accent:#6fc2a0;
--risk:#ff8a80;--risk-bg:#3a1d1b;--warn:#ffb74d;--warn-bg:#352a17;--ok:#7fd3a6;--ok-bg:#16301f;--unk:#e6d36b;--unk-bg:#2f2b14;--code:#25272b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 16px 48px}
p,li{overflow-wrap:anywhere}
h1{font-size:28px;line-height:1.25;margin:4px 0 8px}
h2{font-size:21px;margin:0}
h3{font-size:16px;margin:28px 0 8px}
h4{font-size:15px;margin:22px 0 8px}
.eyebrow{margin:0;color:var(--accent);font-weight:600;letter-spacing:.04em;text-transform:uppercase;font-size:12px}
.meta{color:var(--muted);margin:0 0 6px}
.fineprint,.hint{color:var(--muted);font-size:13px}
.banner{margin-top:14px;padding:12px 14px;border-radius:8px;background:var(--unk-bg);color:var(--ink);border:1px solid var(--line)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}
.card{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:4px;border-top:3px solid var(--accent)}
.card.risk{border-top-color:var(--risk)}.card.unknown{border-top-color:var(--unk)}.card.ok{border-top-color:var(--ok)}.card.warn{border-top-color:var(--warn)}
.num{font-size:28px;font-weight:650;font-variant-numeric:tabular-nums}.num small{font-size:15px;color:var(--muted);font-weight:500}
.lbl{color:var(--muted);font-size:13px}
.toc{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px}
.toc a{color:var(--accent);text-decoration:none;border:1px solid var(--line);background:var(--paper);border-radius:999px;padding:4px 12px;font-size:13px}
.clause{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:22px 22px 18px;margin:0 0 18px}
.clause-head{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:8px}
.clause-head .title{display:block;font-weight:500;color:var(--muted);font-size:15px;margin-top:2px}
.due{font-size:13px;font-weight:600;color:var(--accent);border:1px solid var(--line);border-radius:6px;padding:2px 8px;white-space:nowrap}
.quote{margin:12px 0 4px;padding:2px 0 2px 14px;border-left:3px solid var(--accent)}
.quote p{margin:6px 0}.quote ul{margin:6px 0;padding-left:18px;list-style:none}.quote li{margin:4px 0}
.quote cite{display:block;color:var(--muted);font-size:12px;font-style:normal;margin-top:4px}
.label{font-size:13px;font-weight:500;color:var(--muted)}
.circular{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:12px 0 8px;font-size:14px}
.circular dt{color:var(--muted);font-weight:600}.circular dd{margin:0}
.quote.lead{margin:0 0 18px}.quote.lead p{font-weight:600}
@media (max-width:720px){.circular{grid-template-columns:1fr}.circular dd{margin-bottom:6px}}
.assume{color:var(--warn)}
.split{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.split h3{margin-top:12px}
.split ul{margin:0;padding-left:18px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid var(--line)}
th{font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
td.strong{font-weight:650}
.sub{color:var(--muted);font-size:12px;margin-top:2px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:12px;background:var(--code)}
.kex-hybrid,.legacy-no{background:var(--ok-bg);color:var(--ok)}
.kex-classical,.legacy-yes{background:var(--warn-bg);color:var(--warn)}
.kex-unknown,.legacy-unknown{background:var(--unk-bg);color:var(--unk)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.s-at_risk{background:var(--risk-bg);color:var(--risk)}
.s-unknown{background:var(--unk-bg);color:var(--unk)}
.s-not_at_risk,.s-mitigated_pq_clients{background:var(--ok-bg);color:var(--ok)}
.warn-text{color:var(--warn)}
td .badge{white-space:normal}
.link{overflow-wrap:anywhere}.link a,.counts a{color:var(--accent)}
td.n .scope{font-weight:400}
.figure{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px;margin:6px 0}
.figure .big{font-size:30px;font-weight:650;font-variant-numeric:tabular-nums}
.counts,.limits{padding-left:18px}
.counts a{color:var(--accent)}
.empty{color:var(--muted);font-style:italic}
.actions{border-top:1px solid var(--line);margin-top:6px}
.rank{display:inline-block;min-width:22px;text-align:center;border-radius:6px;background:var(--code);font-size:12px;padding:1px 4px}
table.plain th{text-transform:none;letter-spacing:0;font-size:12.5px}
.cmd{background:var(--code);border-radius:8px;padding:12px;overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:24px}
@media (max-width:720px){.split{grid-template-columns:1fr}h1{font-size:23px}.clause{padding:16px}}
@media print{body{background:#fff;font-size:11.5px}main{max-width:none;padding:0}.toc{display:none}
.clause,.card{border-color:#ccc;break-inside:avoid-page}.scroll{overflow:visible}a{color:inherit}}
`
