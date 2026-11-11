package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// labReport is the test lab's shape: A hybrid, B classical with TLS 1.3, C a
// vendor without TLS 1.3 and with legacy protocols, D unreachable. A and B
// share an ECDSA certificate and C has an RSA one; both expire 29 days after
// the scan and chain to no trusted root.
func labReport(t *testing.T) (RiskReport, Report) {
	t.Helper()
	scanAt := time.Date(2026, 11, 9, 20, 0, 0, 0, time.UTC)
	cert := func(ref, alg string) Certificate {
		return Certificate{Ref: "sha256:" + ref, Issuer: "CN=lab-" + alg, PublicKey: PublicKey{Algorithm: alg},
			NotAfter: time.Date(2026, 12, 8, 12, 0, 0, 0, time.UTC), Verification: Verification{HostnameMatch: "not_checked", Validity: "valid"}}
	}
	ts := []Target{hybridSrv("a:1"), classical13("b:1"), noTLS13("c:1"), unreachable("d:1")}
	ts[0].Certificates = []Certificate{cert("eeee1111eeee", "ECDSA")}
	ts[1].Certificates = []Certificate{cert("eeee1111eeee", "ECDSA")}
	ts[2].Certificates = []Certificate{cert("aaaa2222aaaa", "RSA")}
	for i := range ts {
		ts[i].ScannedAt = scanAt
	}
	scan := Report{SchemaVersion: schemaVersion, Targets: ts}
	mapping := []MappingEntry{
		{Target: "a:1", System: "Lab A", Owner: "Web team", DataClassification: "Secret", ThirdParty: "in-house"},
		{Target: "b:1", System: "Lab B", Owner: "Platform team", DataClassification: "Restricted", ThirdParty: "in-house"},
		{Target: "c:1", System: "Lab C", Owner: "Integration team", DataClassification: "Secret", ThirdParty: "Example Vendor", Constraints: "Settings fixed by firmware"},
		{Target: "d:1", System: "Lab D", Owner: "Operations", DataClassification: "Top Secret", ThirdParty: "in-house"},
	}
	pol := fullPolicy()
	pol.ClassificationLevels[2].ShelfLife = sourced(10) // Restricted: X 10 > Z 9
	return buildReport(scan, Inputs{ScanGeneratedAt: scanAt}, mapping, pol, scanAt), scan
}

func TestAgilityIndicative(t *testing.T) {
	r, _ := labReport(t)
	got := map[string]string{}
	for _, a := range r.Assets {
		got[a.Target] = a.AgilityIndicative.Level + "/" + a.AgilityIndicative.YKnown
	}
	want := map[string]string{"a:1": "in_place/default", "b:1": "upgrade/default", "c:1": "vendor_bound/no"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: agility = %s, want %s", k, got[k], v)
		}
	}
	for _, a := range r.Assets {
		if a.Target == "c:1" && a.AgilityIndicative.Ask != "A dated plan for TLS 1.3 and hybrid key exchange, with the migration time (Y); until then, disabling legacy protocols and weak suites." {
			t.Errorf("c ask = %q", a.AgilityIndicative.Ask)
		}
	}
}

func TestInitiatives(t *testing.T) {
	r, _ := labReport(t)
	var got []string
	for _, in := range r.Initiatives {
		got = append(got, in.ID+" "+in.Title+" | "+in.Assets+" | "+in.Depends)
	}
	want := []string{
		"I1 Enable hybrid key exchange (X25519MLKEM768) | Lab C and Lab B | Lab C needs TLS 1.3 first and a vendor timeline; Lab B may need a TLS library upgrade",
		"I2 Retire TLS 1.0, TLS 1.1 and RSA key transport | Lab C | Settings fixed by firmware; Example Vendor",
		"I3 Move certificates to a post-quantum signature (ML-DSA) | 2 certificates on 3 endpoints | CA and client support for ML-DSA",
		"I4 Renew certificates that expire soon or have expired | 2 certificates on 3 endpoints | Expiry dates in the Certificates table",
		"I5 Confirm private trust for internal-CA certificates | 2 certificates on 3 endpoints | —",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("initiatives:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Every action but the third-party ask and the "no change now" one names its initiative.
	for _, a := range r.Assets {
		for _, f := range a.Findings {
			none := f.Area == "third_party" || strings.HasPrefix(f.Finding, "Hybrid key exchange available")
			if none != (f.Initiative == "") {
				t.Errorf("%s %s: initiative %q", a.Target, f.Finding, f.Initiative)
			}
		}
	}
}

func TestCertificateExpiryFinding(t *testing.T) {
	r, _ := labReport(t)
	c := r.Assets[0] // Lab C, first in priority order
	if c.Target != "c:1" || c.Findings[0].Area != "third_party" {
		t.Fatalf("first asset %s, first finding %+v", c.Target, c.Findings[0])
	}
	var exp []string
	for _, f := range c.Findings {
		if f.Area == "certificate_expiry" {
			exp = append(exp, f.Finding)
		}
	}
	if len(exp) != 1 || exp[0] != "Certificate aaaa2222 expires 2026-12-08, 29 days after the scan" {
		t.Errorf("expiry findings = %q", exp)
	}
}

func TestCommitteeItems(t *testing.T) {
	r, _ := labReport(t)
	var got []string
	for _, k := range r.CommitteeItems {
		got = append(got, k.Kind+": "+k.Ask+" | "+k.Why+" | "+k.Owner+" | "+k.Due)
	}
	want := []string{
		"missing_value: Ask Example Vendor for a dated migration plan for Lab C. | Secret data, at risk (margin ≥ +1), accepts TLS 1.0, TLS 1.1 and RSA key transport, settings fixed by firmware. | Integration team | Before end of Q4 2026",
		"not_assessed: Restore reachability of Lab D, then rescan. | It is mapped, but nothing about its TLS is known; Clause 2 completeness stays at 3 of 4 until it is assessed. | Operations | Before end of Q4 2026",
		"out_of_scope: Approve the scope and an owner for cryptographic assets other than TLS endpoints. | SSH, VPN, HSMs and key stores, application code and databases are outside this scan; Clause 2 covers all cryptographic assets. | Information security committee | Decision",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("committee items:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestHTMLGroup3(t *testing.T) {
	r, scan := labReport(t)
	var b bytes.Buffer
	if err := writeHTML(&b, r, scan.Targets); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, want := range []string{
		`<span class="tag c-risk">Vendor-bound</span>`, `The agility level is indicative`,
		`<a class="tag c-neutral ini" href="#plans">I1</a>`,
		`<span class="tag c-risk">29 days</span>`, `2 certificates on 3 endpoints · 2 expire within 30 days`,
		`certificates expire within 30 days</a>`,
		`<span class="tag c-na">unreachable</span> <span class="dim small">all 7 probes ended in error: `,
		`Restore reachability of Lab D, then rescan.`,
		`clause texts are in SAMA Circular above`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(page, `id="g-clause1"`) {
		t.Error("glossary repeats clause texts")
	}
}

// The one-page summary: headline with the Clause 2 deadline, no "Not tested",
// no "+N more", plain-language exposure.
func TestSummaryPage(t *testing.T) {
	r, scan := labReport(t)
	var b bytes.Buffer
	if err := writeHTML(&b, r, scan.Targets); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	sum := page[strings.Index(page, `<section class="sumpage"`):]
	sum = sum[:strings.Index(sum, `</section>`)]
	for _, want := range []string{
		`2 of 3 assessed TLS endpoints are at risk from quantum computing. 1 more could not be assessed. Clause 2 (inventory) is due in 52 days.`,
		`Partial: TLS only, 3 of 4`, `<strong>52 days</strong>`, `5 initiatives proposed`, `3 items to escalate`,
		`1 of them waits on its vendor`, `<strong>at least 1.0 years</strong>`, `assumes 1 year to migrate`, `Older clients only`,
		`Get a dated plan from the vendor; switch off old protocols (TLS 1.0, 1.1).`,
		`Restore reachability of Lab D, then rescan.`,
		`2 certificates expire within 30 days of the scan, the first on 2026-12-08 (operational, not quantum).`,
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
	for _, bad := range []string{"Not tested", "more</span>", "+1 more", "dark"} {
		if strings.Contains(sum, bad) {
			t.Errorf("summary contains %q", bad)
		}
	}
	// The summary's short forms never leak into the full report's Clause coverage.
	if !strings.Contains(page, `<span class="tag c-unk">52 days left</span>`) {
		t.Error("Clause coverage lost \"days left\"")
	}
	if strings.Contains(page, "prefers-color-scheme") || strings.Contains(page, `data-theme="dark"`) {
		t.Error("the report is light only")
	}
}
