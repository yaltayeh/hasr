package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/yaltayeh/hasr/internal/cloud"
)

// Synthetic cloud records for the join tests (no real account or hostnames).

func cloudEndpoint(name, host string, port int, kex, legacy string, managed bool, labels map[string]string) cloud.Endpoint {
	e := cloud.Endpoint{
		Provider: "aws", Scope: "eu-north-1", ResourceID: "listener/" + name + "/" + host, ResourceKind: "load_balancer_listener",
		Name: name, Hostnames: []string{host}, Port: port, Protocol: "HTTPS", Exposure: "internet", Labels: labels,
	}
	if kex != "" {
		e.TLS = &cloud.TLS{
			Policy:             cloud.Policy{Name: name + "-policy", Managed: managed, ContentsKnown: true},
			Versions:           []string{"TLS 1.2", "TLS 1.3"},
			KeyExchange:        kex,
			KeyExchangeReasons: []string{"test reason"},
			Legacy:             legacy,
			LegacyReasons:      []string{},
			Certificates:       []cloud.Certificate{},
		}
		if legacy == "yes" {
			e.TLS.LegacyReasons = []string{"policy allows TLS 1.0"}
		}
	} else {
		e.Protocol = "HTTP"
		e.Notes = []string{"no TLS at the load balancer"}
	}
	return e
}

func inventory(eps ...cloud.Endpoint) cloudFile {
	return cloudFile{Path: "aws.json", Inv: cloud.Inventory{
		Kind: cloud.Kind, SchemaVersion: cloud.SchemaVersion, Provider: "aws",
		Scopes:    []cloud.Scope{{Scope: "eu-north-1", Status: cloud.ScopeRead}},
		NotRead:   []cloud.Limit{{ID: "aws_other_regions", Detail: "only eu-north-1"}},
		Endpoints: eps,
	}}
}

func TestCloudJoin(t *testing.T) {
	// a: hybrid on both sides, managed policy.
	a := hybridSrv("pq.example:443")
	// b: classical on both sides, managed policy, in-house: Y is the managed default.
	b := classical13("default.example:443")
	// c: the scan sees hybrid (a CDN in front) but the cloud record is classical: worst counts.
	c := hybridSrv("cdn.example:443")
	// d: reached through a CNAME to the load balancer's name.
	d := classical13("app.example:443")
	d.CanonicalName = "lb-d.elb.example"

	scan := Report{SchemaVersion: schemaVersion, Targets: []Target{a, b, c, d}}
	mapping := []MappingEntry{
		{Target: "pq.example:443", System: "Payments", DataClassification: "Secret", ThirdParty: "in-house"},
		{Target: "default.example:443", System: "Portal", DataClassification: "Secret", ThirdParty: "in-house"},
		{Target: "cdn.example:443", System: "Web", DataClassification: "Restricted", ThirdParty: "in-house"},
		// Owner and service empty: tags may fill them; data_classification is never taken from tags.
		{Target: "app.example:443", System: "App", Owner: "", DataClassification: "Secret", ThirdParty: "in-house"},
	}
	inv := inventory(
		cloudEndpoint("lb-a", "pq.example", 443, "hybrid", "no", true, nil),
		cloudEndpoint("lb-b", "default.example", 443, "classical", "yes", true, nil),
		cloudEndpoint("lb-c", "cdn.example", 443, "classical", "no", true, nil),
		cloudEndpoint("lb-d", "lb-d.elb.example", 443, "classical", "no", true,
			map[string]string{"Owner": "Team D (sample)", "service": "API", "data_classification": "Public"}),
		cloudEndpoint("lb-e", "unlisted.elb.example", 443, "classical", "yes", true, nil),
		cloudEndpoint("lb-e", "unlisted.elb.example", 80, "", "", false, nil),
	)
	inv.Inv.Endpoints[1].TLS.Recommendation = &cloud.Recommendation{
		Action: "Switch to PQ-POLICY; test client compatibility first.", Links: []string{"https://docs.example/policies"},
		Effects: []string{"adds TLS 1.3", "removes RSA key transport suites"},
	}
	r := buildReport(scan, Inputs{}, mapping, fullPolicy(), time.Unix(0, 0), inv)

	byTarget := map[string]Asset{}
	for _, as := range r.Assets {
		byTarget[as.Target] = as
	}

	if got := byTarget["pq.example:443"]; got.KeyExchange != "hybrid" || len(got.Cloud) != 1 || got.Cloud[0].Match != "hostname" {
		t.Errorf("pq: kex %s, cloud %+v", got.KeyExchange, got.Cloud)
	}
	if got := byTarget["default.example:443"]; got.Mosca.YSource != "default for managed TLS policy (cloud)" || *got.Mosca.Y != 0.5 {
		t.Errorf("default: Y %v from %q, want 0.5 from the managed TLS default", got.Mosca.Y, got.Mosca.YSource)
	}
	if got := byTarget["default.example:443"]; got.Legacy != "yes" {
		t.Errorf("default: legacy %s, want yes (cloud record says yes)", got.Legacy)
	}
	// The managed record's recommendation replaces the scan's action; the scan's evidence stays.
	var kexFindings []Finding
	for _, fd := range byTarget["default.example:443"].Findings {
		if fd.Area == "key_exchange" {
			kexFindings = append(kexFindings, fd)
		}
	}
	if len(kexFindings) != 1 {
		t.Fatalf("default: %d key-exchange findings, want 1 (the record's is not repeated): %+v", len(kexFindings), kexFindings)
	}
	kf := kexFindings[0]
	if !strings.HasPrefix(kf.Finding, "Classical key exchange only; TLS 1.3 is available. Cloud record: aws lb-b uses the managed TLS policy lb-b-policy; this single switch adds TLS 1.3, removes RSA key transport suites") ||
		kf.Action != "Switch to PQ-POLICY; test client compatibility first. Source: https://docs.example/policies" {
		t.Errorf("default key-exchange finding = %+v", kf)
	}
	cdn := byTarget["cdn.example:443"]
	if cdn.KeyExchange != "classical" || cdn.Mosca.Status == statusMitigated {
		t.Errorf("cdn: kex %s status %s; the worse (classical) must count", cdn.KeyExchange, cdn.Mosca.Status)
	}
	var kexDis *Disagreement
	for i, dd := range r.Disagreements {
		if dd.Target == "cdn.example:443" && dd.Field == "key_exchange" {
			kexDis = &r.Disagreements[i]
		}
	}
	if kexDis == nil || kexDis.Scan != "hybrid" || kexDis.Counted != "classical" {
		t.Errorf("cdn disagreement = %+v, in %+v", kexDis, r.Disagreements)
	}

	app := byTarget["app.example:443"]
	if len(app.Cloud) != 1 || app.Cloud[0].Match != "cname" {
		t.Errorf("app: cloud %+v, want a cname match", app.Cloud)
	}
	if app.Mapping.Owner != "Team D (sample)" || app.Mapping.Service != "API" {
		t.Errorf("app: owner %q service %q, want them from tags", app.Mapping.Owner, app.Mapping.Service)
	}
	if app.Mapping.DataClassification != "Secret" || app.FieldSources["data_classification"] != "" {
		t.Errorf("app: data_classification %q came from a tag", app.Mapping.DataClassification)
	}
	if !strings.Contains(app.FieldSources["owner"], `tag "Owner" on aws lb-d`) {
		t.Errorf("app: owner source %q", app.FieldSources["owner"])
	}
	if mapping[3].Owner != "" {
		t.Error("filling from tags changed the caller's mapping slice")
	}

	// The mapping file wins over tags.
	if byTarget["pq.example:443"].FieldSources != nil {
		t.Errorf("pq: field sources %v, want none", byTarget["pq.example:443"].FieldSources)
	}

	// lb-e (two listeners) matched nothing: found in the cloud, not in the target list.
	if len(r.CloudDiscovered) != 2 || r.Completeness.CloudDiscovered != 2 || r.Completeness.Known() != 6 {
		t.Errorf("discovered %d (completeness %d, known %d), want 2, 2, 6", len(r.CloudDiscovered), r.Completeness.CloudDiscovered, r.Completeness.Known())
	}
	if len(byTarget["default.example:443"].Agility) != 1 {
		t.Errorf("agility evidence = %v", byTarget["default.example:443"].Agility)
	}
	if len(r.CloudLimits) != 1 {
		t.Errorf("cloud limits = %v", r.CloudLimits)
	}

	var page bytes.Buffer
	if err := writeHTML(&page, r, scan.Targets); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Found in the cloud, not in the target list", "Scan and cloud records disagree",
		"cname match", "from tag &#34;Owner&#34; on aws lb-d", "Default Y: managed TLS policy (cloud)", "--cloud aws.json",
		"known targets (4 mapped, plus 2 found in the cloud"} {
		if !strings.Contains(page.String(), want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
}

func TestCloudJoinWithoutCloud(t *testing.T) {
	scan := Report{SchemaVersion: schemaVersion, Targets: []Target{classical13("x.example:443")}}
	r := buildReport(scan, Inputs{}, []MappingEntry{{Target: "x.example:443", DataClassification: "Secret", ThirdParty: "in-house"}}, fullPolicy(), time.Unix(0, 0))
	if r.Assets[0].Mosca.YSource != "default for TLS 1.3, classical key exchange" {
		t.Errorf("without cloud records the scan category must apply, got %q", r.Assets[0].Mosca.YSource)
	}
	var page bytes.Buffer
	if err := writeHTML(&page, r, scan.Targets); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page.String(), "Found in the cloud") {
		t.Error("cloud sections shown without --cloud input")
	}
}
