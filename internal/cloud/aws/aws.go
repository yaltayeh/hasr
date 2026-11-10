// Package aws converts a folder written by collectors/aws/collect.sh (raw AWS
// CLI JSON plus manifest.json) into the provider-neutral cloud.Inventory.
// It reads files only: it makes no AWS calls and holds no credentials.
//
// The AWS-specific rules live here, each with its basis and source link:
// "PQ in the policy name" for hybrid key exchange, and the reading of
// OpenSSL-style cipher names for RSA key transport, 3DES and RC4.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yaltayeh/hasr/internal/cloud"
)

const Provider = "aws"

// Source documents for the rules applied here.
// recommendedPolicy is AWS's recommended policy for hybrid post-quantum key
// exchange with backward compatibility (TLS 1.2 and 1.3), per the ALB docs.
const recommendedPolicy = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"

const (
	docALBPolicies = "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html"
	docNLBPolicies = "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html"
)

// --- Raw shapes (only the fields used; the CLI returns more) ---

type manifest struct {
	Kind             string   `json:"kind"`
	CollectorVersion string   `json:"collector_version"`
	CLIVersion       string   `json:"cli_version"`
	StartedAt        string   `json:"started_at"`
	FinishedAt       string   `json:"finished_at"`
	Regions          []string `json:"regions"`
	Refused          string   `json:"refused"`
	Calls            []call   `json:"calls"`
}

type call struct {
	Service    string   `json:"service"`
	Operation  string   `json:"operation"`
	Args       []string `json:"args"`
	Region     string   `json:"region"`
	Output     string   `json:"output"`
	Stderr     string   `json:"stderr"`
	ExitStatus int      `json:"exit_status"`
}

// arg returns the value after flag in the call's args.
func (c call) arg(flag string) string {
	for i := 0; i+1 < len(c.Args); i++ {
		if c.Args[i] == flag {
			return c.Args[i+1]
		}
	}
	return ""
}

type loadBalancers struct {
	LoadBalancers []struct {
		LoadBalancerArn  string `json:"LoadBalancerArn"`
		LoadBalancerName string `json:"LoadBalancerName"`
		DNSName          string `json:"DNSName"`
		Scheme           string `json:"Scheme"`
		Type             string `json:"Type"`
	} `json:"LoadBalancers"`
}

type listeners struct {
	Listeners []struct {
		ListenerArn     string `json:"ListenerArn"`
		LoadBalancerArn string `json:"LoadBalancerArn"`
		Port            int    `json:"Port"`
		Protocol        string `json:"Protocol"`
		SslPolicy       string `json:"SslPolicy"`
		Certificates    []struct {
			CertificateArn string `json:"CertificateArn"`
		} `json:"Certificates"`
	} `json:"Listeners"`
}

type listenerCertificates struct {
	Certificates []struct {
		CertificateArn string `json:"CertificateArn"`
		IsDefault      bool   `json:"IsDefault"`
	} `json:"Certificates"`
}

type sslPolicies struct {
	SslPolicies []sslPolicy `json:"SslPolicies"`
}

type sslPolicy struct {
	Name         string   `json:"Name"`
	SslProtocols []string `json:"SslProtocols"`
	Ciphers      []struct {
		Name string `json:"Name"`
	} `json:"Ciphers"`
}

type tagDescriptions struct {
	TagDescriptions []struct {
		ResourceArn string `json:"ResourceArn"`
		Tags        []tag  `json:"Tags"`
	} `json:"TagDescriptions"`
}

type tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type acmDescribe struct {
	Certificate struct {
		CertificateArn string `json:"CertificateArn"`
		Subject        string `json:"Subject"`
		DomainName     string `json:"DomainName"`
		Serial         string `json:"Serial"`
		KeyAlgorithm   string `json:"KeyAlgorithm"`
		NotAfter       string `json:"NotAfter"`
		Type           string `json:"Type"`
	} `json:"Certificate"`
}

type acmGet struct {
	Certificate string `json:"Certificate"`
}

// --- Conversion ---

// Convert reads a collector folder and returns its inventory. tool names the
// converter (set by the caller); now is the conversion time.
func Convert(dir string, tool cloud.Tool, now time.Time) (cloud.Inventory, error) {
	var m manifest
	if err := readJSON(filepath.Join(dir, "manifest.json"), &m); err != nil {
		return cloud.Inventory{}, fmt.Errorf("reading manifest: %w", err)
	}
	if m.Kind != "hasr-aws-raw" {
		return cloud.Inventory{}, fmt.Errorf("manifest kind %q, want hasr-aws-raw", m.Kind)
	}
	if m.Refused != "" {
		return cloud.Inventory{}, fmt.Errorf("the collector refused to run (%s); nothing was collected", m.Refused)
	}
	c := &converter{dir: dir, m: m}
	inv := cloud.Inventory{
		Kind:          cloud.Kind,
		SchemaVersion: cloud.SchemaVersion,
		Tool:          tool,
		GeneratedAt:   now,
		Provider:      Provider,
		Collection: cloud.Collection{
			Collector:        "collectors/aws/collect.sh",
			CollectorVersion: m.CollectorVersion,
			StartedAt:        parseTime(m.StartedAt),
			FinishedAt:       parseTime(m.FinishedAt),
			Calls:            len(m.Calls),
		},
		Scopes: []cloud.Scope{},
		ResourceTypesRead: []string{
			"Elastic Load Balancing v2 load balancers (Application, Network, Gateway) and their listeners",
			"Elastic Load Balancing v2 SSL policies",
			"listener certificates",
			"ACM certificates",
			"tags on load balancers and ACM certificates",
		},
		NotRead:   notRead(m.Regions),
		Endpoints: []cloud.Endpoint{},
	}
	for _, cl := range m.Calls {
		if cl.ExitStatus != 0 {
			inv.Collection.FailedCalls++
		}
	}
	for _, region := range m.Regions {
		scope, eps := c.region(region)
		inv.Scopes = append(inv.Scopes, scope)
		inv.Endpoints = append(inv.Endpoints, eps...)
	}
	sort.Slice(inv.Endpoints, func(i, j int) bool {
		a, b := inv.Endpoints[i], inv.Endpoints[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Port < b.Port
	})
	if err := inv.Validate(); err != nil {
		return cloud.Inventory{}, fmt.Errorf("converted inventory is invalid: %w", err)
	}
	return inv, nil
}

func notRead(regions []string) []cloud.Limit {
	return []cloud.Limit{
		{ID: "aws_other_regions", Detail: "only these regions were read: " + strings.Join(regions, ", ")},
		{ID: "aws_other_services", Detail: "not read: CloudFront, API Gateway, Classic Load Balancers, KMS keys and other services that terminate TLS or hold keys"},
		{ID: "aws_backend_tls", Detail: "TLS from a load balancer to its targets: AWS picks that policy from the listener's policy; the API does not show it per listener"},
		{ID: "aws_key_exchange_groups", Detail: "key-exchange groups: DescribeSSLPolicies returns protocols and ciphers only, so hybrid key exchange is read from the policy name"},
		{ID: "aws_iam_server_certificates", Detail: "certificates stored in IAM (not ACM) are listed by ARN only"},
	}
}

type converter struct {
	dir string
	m   manifest
}

// calls returns the region's calls for one operation.
func (c *converter) calls(region, op string) []call {
	var out []call
	for _, cl := range c.m.Calls {
		if cl.Region == region && cl.Operation == op {
			out = append(out, cl)
		}
	}
	return out
}

func (c *converter) failure(cl call) string {
	msg := "exit status " + fmt.Sprint(cl.ExitStatus)
	if cl.Stderr != "" {
		if b, err := os.ReadFile(filepath.Join(c.dir, cl.Stderr)); err == nil {
			if line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)[0]); line != "" {
				msg = line
			}
		}
	}
	return fmt.Sprintf("%s %s failed: %s", cl.Service, cl.Operation, msg)
}

// load reads a successful call's output; ok is false if the call failed or
// the file is unreadable. A failed call's problem is "": region() has already
// recorded every failed call of the region.
func (c *converter) load(cl call, v any) (ok bool, problem string) {
	if cl.ExitStatus != 0 {
		return false, ""
	}
	if err := readJSON(filepath.Join(c.dir, cl.Output), v); err != nil {
		return false, fmt.Sprintf("%s %s: unreadable output: %v", cl.Service, cl.Operation, err)
	}
	return true, ""
}

func (c *converter) region(region string) (cloud.Scope, []cloud.Endpoint) {
	scope := cloud.Scope{Scope: region, Status: cloud.ScopeRead}
	problem := func(p string) {
		if p == "" {
			return
		}
		scope.Errors = append(scope.Errors, p)
		if scope.Status == cloud.ScopeRead {
			scope.Status = cloud.ScopePartial
		}
	}

	// Every failed call is recorded first, so none is hidden.
	for _, cl := range c.m.Calls {
		if cl.Region == region && cl.ExitStatus != 0 && cl.Operation != "get-caller-identity" {
			problem(c.failure(cl))
		}
	}

	// SSL policies by name.
	policies := map[string]sslPolicy{}
	for _, cl := range c.calls(region, "describe-ssl-policies") {
		var sp sslPolicies
		if ok, p := c.load(cl, &sp); ok {
			for _, pol := range sp.SslPolicies {
				policies[pol.Name] = pol
			}
		} else {
			problem(p)
		}
	}

	// Certificates by ARN.
	certs := c.certificates(region, problem)

	// Load balancers.
	lbCalls := c.calls(region, "describe-load-balancers")
	if len(lbCalls) == 0 {
		scope.Status = cloud.ScopeFailed
		scope.Errors = append(scope.Errors, "load balancers were not read")
		return scope, nil
	}
	var lbs loadBalancers
	if ok, p := c.load(lbCalls[0], &lbs); !ok {
		scope.Status = cloud.ScopeFailed
		if p != "" {
			scope.Errors = append(scope.Errors, p)
		}
		return scope, nil
	}

	tags := map[string]map[string]string{}
	for _, cl := range c.calls(region, "describe-tags") {
		var td tagDescriptions
		if ok, p := c.load(cl, &td); ok {
			for _, d := range td.TagDescriptions {
				tags[d.ResourceArn] = tagMap(d.Tags)
			}
		} else {
			problem(p)
		}
	}

	listenerCerts := map[string]listenerCertificates{}
	for _, cl := range c.calls(region, "describe-listener-certificates") {
		var lc listenerCertificates
		if ok, p := c.load(cl, &lc); ok {
			listenerCerts[cl.arg("--listener-arn")] = lc
		} else {
			problem(p)
		}
	}

	listenersByLB := map[string]listeners{}
	readLB := map[string]bool{}
	for _, cl := range c.calls(region, "describe-listeners") {
		lbArn := cl.arg("--load-balancer-arn")
		var ls listeners
		if ok, p := c.load(cl, &ls); ok {
			listenersByLB[lbArn] = ls
			readLB[lbArn] = true
		} else {
			problem(p)
		}
	}

	var eps []cloud.Endpoint
	for _, lb := range lbs.LoadBalancers {
		if !readLB[lb.LoadBalancerArn] {
			problem("listeners of load balancer " + lb.LoadBalancerName + " were not read")
			continue
		}
		labels := tags[lb.LoadBalancerArn]
		if labels == nil {
			labels = map[string]string{}
		}
		for _, l := range listenersByLB[lb.LoadBalancerArn].Listeners {
			e := cloud.Endpoint{
				Provider:     Provider,
				Scope:        region,
				ResourceID:   l.ListenerArn,
				ResourceKind: "load_balancer_listener",
				Name:         lb.LoadBalancerName,
				Hostnames:    []string{strings.ToLower(strings.TrimSuffix(lb.DNSName, "."))},
				Port:         l.Port,
				Protocol:     l.Protocol,
				Exposure:     exposure(lb.Scheme),
				Labels:       labels,
			}
			switch l.Protocol {
			case "HTTPS", "TLS":
				e.TLS = tlsInfo(l.SslPolicy, policies, lb.Type)
				e.TLS.Certificates = listenerCertificateList(l.ListenerArn, l.Certificates, listenerCerts, certs, &e)
			case "HTTP":
				e.Notes = append(e.Notes, "no TLS at the load balancer: plaintext HTTP listener")
			default:
				e.Notes = append(e.Notes, l.Protocol+" listener: any TLS is terminated by the targets, which the API does not show; scan the endpoint")
			}
			eps = append(eps, e)
		}
	}
	return scope, eps
}

func exposure(scheme string) string {
	switch scheme {
	case "internet-facing":
		return "internet"
	case "internal":
		return "internal"
	}
	return "unknown"
}

// tlsInfo applies the AWS rules to a listener's policy.
func tlsInfo(name string, policies map[string]sslPolicy, lbType string) *cloud.TLS {
	link := docALBPolicies
	if lbType == "network" {
		link = docNLBPolicies
	}
	t := &cloud.TLS{
		Policy:             cloud.Policy{Name: name, Managed: true},
		Versions:           []string{},
		KeyExchangeReasons: []string{},
		LegacyReasons:      []string{},
		Certificates:       []cloud.Certificate{},
	}
	// Hybrid key exchange: AWS documents it for policies with "PQ" in the name;
	// DescribeSSLPolicies does not list key-exchange groups.
	t.KeyExchangeBasis = cloud.Basis{
		Rule:  `AWS: "Security policies with PQ in their names offer hybrid post-quantum key exchange."`,
		Links: []string{link},
	}
	switch {
	case name == "":
		t.KeyExchange = "unknown"
		t.KeyExchangeReasons = append(t.KeyExchangeReasons, "listener has no security policy name")
	case strings.Contains(name, "PQ"):
		t.KeyExchange = "hybrid"
		t.KeyExchangeReasons = append(t.KeyExchangeReasons, "policy "+name+" has PQ in its name: hybrid key exchange (ML-KEM) offered; classical key exchange still accepted")
	default:
		t.KeyExchange = "classical"
		t.KeyExchangeReasons = append(t.KeyExchangeReasons, "policy "+name+" has no PQ in its name: classical key exchange only")
	}

	if t.KeyExchange == "classical" {
		t.Recommendation = &cloud.Recommendation{
			Action:  "Switch the listener to a PQ security policy (AWS recommends " + recommendedPolicy + "); test client compatibility first.",
			Links:   []string{link},
			Effects: policyEffects(name, recommendedPolicy, policies),
		}
	}

	pol, known := policies[name]
	if !known {
		t.Legacy = "unknown"
		t.LegacyReasons = append(t.LegacyReasons, "contents of policy "+name+" were not read")
		return t
	}
	t.Policy.ContentsKnown = true
	versions := map[string]bool{}
	for _, p := range pol.SslProtocols {
		if v := versionName(p); v != "" {
			versions[v] = true
		}
	}
	for _, v := range []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"} {
		if versions[v] {
			t.Versions = append(t.Versions, v)
		}
	}
	if !versions["TLS 1.3"] {
		t.KeyExchangeReasons = append(t.KeyExchangeReasons, "no TLS 1.3 in the policy: hybrid key exchange needs a protocol upgrade first")
	}
	if versions["TLS 1.0"] {
		t.LegacyReasons = append(t.LegacyReasons, "policy allows TLS 1.0")
	}
	if versions["TLS 1.1"] {
		t.LegacyReasons = append(t.LegacyReasons, "policy allows TLS 1.1")
	}
	var rsaKex, des, rc4 []string
	for _, c := range pol.Ciphers {
		switch why := weakCipher(c.Name); why {
		case "rsa":
			rsaKex = append(rsaKex, c.Name)
		case "3des":
			des = append(des, c.Name)
		case "rc4":
			rc4 = append(rc4, c.Name)
		}
	}
	if len(rsaKex) > 0 {
		t.LegacyReasons = append(t.LegacyReasons, "policy allows RSA key transport suites (no forward secrecy): "+strings.Join(rsaKex, ", "))
	}
	if len(des) > 0 {
		t.LegacyReasons = append(t.LegacyReasons, "policy allows 3DES suites: "+strings.Join(des, ", "))
	}
	if len(rc4) > 0 {
		t.LegacyReasons = append(t.LegacyReasons, "policy allows RC4 suites: "+strings.Join(rc4, ", "))
	}
	if len(t.LegacyReasons) > 0 {
		t.Legacy = "yes"
	} else {
		t.Legacy = "no"
	}
	return t
}

// policyEffects says what switching from one policy to another changes, from
// the policies' contents as read; empty when either policy was not read.
func policyEffects(from, to string, policies map[string]sslPolicy) []string {
	a, okA := policies[from]
	b, okB := policies[to]
	if !okA || !okB {
		return []string{}
	}
	va, vb := versionSet(a), versionSet(b)
	var added, removed []string
	for _, v := range []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"} {
		switch {
		case vb[v] && !va[v]:
			added = append(added, v)
		case va[v] && !vb[v]:
			removed = append(removed, v)
		}
	}
	out := []string{"adds hybrid post-quantum key exchange (ML-KEM)"}
	if len(added) > 0 {
		out = append(out, "adds "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		out = append(out, "removes "+strings.Join(removed, ", "))
	}
	for _, k := range []struct{ kind, label string }{{"rsa", "RSA key transport suites"}, {"3des", "3DES suites"}, {"rc4", "RC4 suites"}} {
		if hasCipher(a, k.kind) && !hasCipher(b, k.kind) {
			out = append(out, "removes "+k.label)
		}
	}
	return out
}

func versionSet(p sslPolicy) map[string]bool {
	m := map[string]bool{}
	for _, v := range p.SslProtocols {
		if n := versionName(v); n != "" {
			m[n] = true
		}
	}
	return m
}

func hasCipher(p sslPolicy, kind string) bool {
	for _, c := range p.Ciphers {
		if weakCipher(c.Name) == kind {
			return true
		}
	}
	return false
}

// versionName maps AWS protocol names to the scan's ("TLS 1.2").
func versionName(p string) string {
	switch p {
	case "TLSv1":
		return "TLS 1.0"
	case "TLSv1.1":
		return "TLS 1.1"
	case "TLSv1.2":
		return "TLS 1.2"
	case "TLSv1.3":
		return "TLS 1.3"
	}
	return ""
}

// weakCipher reads an OpenSSL-style cipher name as AWS lists it. TLS 1.3 suites
// are named TLS_*; (EC)DHE suites have forward secrecy; any other TLS 1.2-and-
// earlier suite (e.g. AES128-GCM-SHA256, AES128-SHA) is RSA key transport.
func weakCipher(name string) string {
	switch {
	case strings.Contains(name, "RC4"):
		return "rc4"
	case strings.Contains(name, "DES-CBC3"), strings.Contains(name, "3DES"):
		return "3des"
	case strings.HasPrefix(name, "TLS_"), strings.HasPrefix(name, "ECDHE-"), strings.HasPrefix(name, "DHE-"):
		return ""
	}
	return "rsa"
}

func listenerCertificateList(listenerArn string, fromListener []struct {
	CertificateArn string `json:"CertificateArn"`
}, all map[string]listenerCertificates, certs map[string]cloud.Certificate, e *cloud.Endpoint) []cloud.Certificate {
	type ref struct {
		arn string
		def bool
	}
	var refs []ref
	if lc, ok := all[listenerArn]; ok {
		for _, c := range lc.Certificates {
			refs = append(refs, ref{c.CertificateArn, c.IsDefault})
		}
	} else {
		// describe-listener-certificates was not read: the listener lists its default only.
		for _, c := range fromListener {
			refs = append(refs, ref{c.CertificateArn, true})
		}
		e.Notes = append(e.Notes, "SNI certificate list not read: only the default certificate is known")
	}
	out := []cloud.Certificate{}
	for _, r := range refs {
		c, ok := certs[r.arn]
		if !ok {
			c = cloud.Certificate{ResourceID: r.arn}
			if strings.Contains(r.arn, ":iam:") {
				c.Origin = "IAM"
			}
		}
		c.Default = r.def
		out = append(out, c)
	}
	return out
}

func (c *converter) certificates(region string, problem func(string)) map[string]cloud.Certificate {
	out := map[string]cloud.Certificate{}
	for _, cl := range c.calls(region, "describe-certificate") {
		var d acmDescribe
		if ok, p := c.load(cl, &d); ok {
			dc := d.Certificate
			subject := dc.Subject
			if subject == "" {
				subject = "CN=" + dc.DomainName
			}
			out[cl.arg("--certificate-arn")] = cloud.Certificate{
				ResourceID:   dc.CertificateArn,
				Subject:      subject,
				Serial:       dc.Serial,
				KeyAlgorithm: dc.KeyAlgorithm,
				NotAfter:     parseTime(dc.NotAfter),
				Origin:       dc.Type,
			}
		} else {
			problem(p)
		}
	}
	for _, cl := range c.calls(region, "get-certificate") {
		arn := cl.arg("--certificate-arn")
		var g acmGet
		if ok, p := c.load(cl, &g); ok {
			ref, err := pemRef(g.Certificate)
			if err != nil {
				problem("certificate body unreadable: " + err.Error())
				continue
			}
			cert := out[arn]
			cert.ResourceID = arn
			cert.Ref = ref
			out[arn] = cert
		} else {
			problem(p)
		}
	}
	return out
}

// pemRef is the scan's certificate ref: sha256 of the leaf's DER.
func pemRef(p string) (string, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("no PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func tagMap(ts []tag) map[string]string {
	m := map[string]string{}
	for _, t := range ts {
		m[t.Key] = t.Value
	}
	return m
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.999999-07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
