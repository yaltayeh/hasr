package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yaltayeh/hasr/internal/cloud"
	"github.com/yaltayeh/hasr/internal/cloud/aws"
)

const collectorScript = "collectors/aws/collect.sh"

// TestCollectorReadOnly is the first guard of DECISIONS.md "Credentials and
// safety": the collector may run only describe-*, list-* and get-* operations.
// (The IAM policy is the second guard; call() checks again at run time.)
func TestCollectorReadOnly(t *testing.T) {
	src, err := os.ReadFile(collectorScript)
	if err != nil {
		t.Fatal(err)
	}
	callRe := regexp.MustCompile(`^call\s+\S+\s+\S+\s+(\S+)\s+([^\s;]+)`)
	awsRe := regexp.MustCompile(`(^|[^A-Za-z0-9_./-])aws\s`)
	calls := 0
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip a trailing "|| ..." and leading "if !" so call lines are recognised anywhere.
		stmt := strings.TrimPrefix(strings.TrimPrefix(line, "if ! "), "if ")
		if m := callRe.FindStringSubmatch(stmt); m != nil {
			calls++
			if !regexp.MustCompile(`^(describe|list|get)-[a-z-]+$`).MatchString(m[2]) {
				t.Errorf("line %d: operation %q (%s) is not describe-*, list-* or get-*", i+1, m[2], m[1])
			}
			continue
		}
		if regexp.MustCompile(`\bset\s+-[a-z]*x`).MatchString(line) {
			t.Errorf("line %d: set -x would echo commands and their arguments", i+1)
		}
		if awsRe.MatchString(line) {
			allowed := strings.Contains(line, `aws --version`) ||
				strings.HasPrefix(line, `aws "$svc" "$op" "$@"`) ||
				strings.HasPrefix(line, `command -v aws`) ||
				strings.HasPrefix(line, `echo `)
			if !allowed {
				t.Errorf("line %d: direct aws invocation outside call(): %s", i+1, line)
			}
		}
	}
	if calls < 8 {
		t.Errorf("found %d call lines; the parser no longer recognises the script", calls)
	}
	// call() refuses anything else at run time too.
	if !strings.Contains(string(src), "describe-*|list-*|get-*) ;;") {
		t.Error("call() no longer checks the operation at run time")
	}
}

// --- Synthetic AWS account for the collector and converter tests ---
// Account 111122223333 is AWS's documentation example, not a real account.

const (
	fakeRegion   = "eu-north-1"
	fakeAccount  = "111122223333"
	lbPQ         = "arn:aws:elasticloadbalancing:eu-north-1:111122223333:loadbalancer/app/demo-pq/aaaa0001"
	lbDefault    = "arn:aws:elasticloadbalancing:eu-north-1:111122223333:loadbalancer/app/demo-default/aaaa0002"
	lnPQ         = "arn:aws:elasticloadbalancing:eu-north-1:111122223333:listener/app/demo-pq/aaaa0001/bbbb0001"
	lnDefault443 = "arn:aws:elasticloadbalancing:eu-north-1:111122223333:listener/app/demo-default/aaaa0002/bbbb0002"
	lnDefault80  = "arn:aws:elasticloadbalancing:eu-north-1:111122223333:listener/app/demo-default/aaaa0002/bbbb0003"
	certArn      = "arn:aws:acm:eu-north-1:111122223333:certificate/cccc0001"
	dnsPQ        = "demo-pq-1.eu-north-1.elb.amazonaws.com"
	dnsDefault   = "demo-default-2.eu-north-1.elb.amazonaws.com"
)

type obj = map[string]any

// fakeAWS writes the response files for testdata/aws and returns the fake's
// folder plus the certificate ref the converter should compute.
func fakeAWS(t *testing.T, root bool) (dir, ref string) {
	t.Helper()
	dir = t.TempDir()
	certPEM, ref := testCertificate(t)
	arn := "arn:aws:sts::" + fakeAccount + ":assumed-role/hasr-readonly/session"
	if root {
		arn = "arn:aws:iam::" + fakeAccount + ":root"
	}
	files := map[string]any{
		"sts_get-caller-identity": obj{"UserId": "AROAEXAMPLE:session", "Account": fakeAccount, "Arn": arn},
		"elbv2_describe-ssl-policies": obj{"SslPolicies": []obj{
			{"Name": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", "SslProtocols": []string{"TLSv1.2", "TLSv1.3"},
				"Ciphers": []obj{{"Name": "TLS_AES_128_GCM_SHA256", "Priority": 1}, {"Name": "ECDHE-RSA-AES128-GCM-SHA256", "Priority": 2}}},
			{"Name": "ELBSecurityPolicy-2016-08", "SslProtocols": []string{"TLSv1", "TLSv1.1", "TLSv1.2"},
				"Ciphers": []obj{{"Name": "ECDHE-RSA-AES128-GCM-SHA256", "Priority": 1}, {"Name": "AES128-GCM-SHA256", "Priority": 2}, {"Name": "AES128-SHA", "Priority": 3}}},
		}},
		"elbv2_describe-load-balancers": obj{"LoadBalancers": []obj{
			{"LoadBalancerArn": lbPQ, "LoadBalancerName": "demo-pq", "DNSName": dnsPQ, "Scheme": "internet-facing", "Type": "application"},
			{"LoadBalancerArn": lbDefault, "LoadBalancerName": "demo-default", "DNSName": dnsDefault, "Scheme": "internet-facing", "Type": "application"},
		}},
		"elbv2_describe-tags_aaaa0001": obj{"TagDescriptions": []obj{{"ResourceArn": lbPQ, "Tags": []obj{{"Key": "Project", "Value": "demo"}, {"Key": "owner", "Value": "Payments team (sample)"}}}}},
		"elbv2_describe-tags_aaaa0002": obj{"TagDescriptions": []obj{{"ResourceArn": lbDefault, "Tags": []obj{}}}},
		"elbv2_describe-listeners_aaaa0001": obj{"Listeners": []obj{
			{"ListenerArn": lnPQ, "LoadBalancerArn": lbPQ, "Port": 443, "Protocol": "HTTPS",
				"Certificates": []obj{{"CertificateArn": certArn}}, "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"},
		}},
		"elbv2_describe-listeners_aaaa0002": obj{"Listeners": []obj{
			// An HTTP listener whose redirect action names HTTPS: the collector must not treat it as TLS.
			{"ListenerArn": lnDefault80, "LoadBalancerArn": lbDefault, "Port": 80, "Protocol": "HTTP",
				"DefaultActions": []obj{{"Type": "redirect", "RedirectConfig": obj{"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}}},
			{"ListenerArn": lnDefault443, "LoadBalancerArn": lbDefault, "Port": 443, "Protocol": "HTTPS",
				"Certificates": []obj{{"CertificateArn": certArn}}, "SslPolicy": "ELBSecurityPolicy-2016-08"},
		}},
		"elbv2_describe-listener-certificates_bbbb0001": obj{"Certificates": []obj{{"CertificateArn": certArn, "IsDefault": true}}},
		"elbv2_describe-listener-certificates_bbbb0002": obj{"Certificates": []obj{{"CertificateArn": certArn, "IsDefault": true}}},
		"acm_list-certificates":                         obj{"CertificateSummaryList": []obj{{"CertificateArn": certArn, "DomainName": "hasr-demo.example"}}},
		"acm_describe-certificate_cccc0001": obj{"Certificate": obj{"CertificateArn": certArn, "DomainName": "hasr-demo.example",
			"Subject": "CN=hasr-demo.example", "Serial": "01", "KeyAlgorithm": "EC_prime256v1", "NotAfter": "2026-11-17T10:00:00+00:00", "Type": "IMPORTED"}},
		"acm_get-certificate_cccc0001":           obj{"Certificate": certPEM},
		"acm_list-tags-for-certificate_cccc0001": obj{"Tags": []obj{}},
	}
	for name, v := range files {
		// Pretty-printed with 4-space indentation, like the AWS CLI.
		b, err := json.MarshalIndent(v, "", "    ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, ref
}

// testCertificate makes a throwaway self-signed certificate at run time, so
// no certificate is ever committed.
func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hasr-demo.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "sha256:" + hex.EncodeToString(sum[:])
}

// runCollector runs collect.sh against the fake aws and returns the raw folder and exit status.
func runCollector(t *testing.T, fakeDir string) (string, int, string) {
	t.Helper()
	abs, err := filepath.Abs("collectors/aws/testdata")
	if err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(t.TempDir(), "raw")
	cmd := exec.Command("sh", collectorScript, "-o", raw, "--region", fakeRegion)
	cmd.Env = append(os.Environ(), "PATH="+abs+":"+os.Getenv("PATH"), "FAKE_AWS_DIR="+fakeDir, "AWS_PROFILE=hasr-readonly")
	out, _ := cmd.CombinedOutput()
	return raw, cmd.ProcessState.ExitCode(), string(out)
}

func TestCollectorAndConverter(t *testing.T) {
	fake, ref := fakeAWS(t, false)
	raw, code, out := runCollector(t, fake)
	if code != 0 {
		t.Fatalf("collector exit %d: %s", code, out)
	}

	// Every AWS call was a read, with explicit --region and --output json.
	log, _ := os.ReadFile(filepath.Join(fake, "invocations.log"))
	for _, l := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		if l == "--version" {
			continue
		}
		f := strings.Fields(l)
		if !regexp.MustCompile(`^(describe|list|get)-`).MatchString(f[1]) {
			t.Errorf("non-read call: %s", l)
		}
		if !strings.Contains(l, "--region "+fakeRegion) || !strings.Contains(l, "--output json") {
			t.Errorf("call without explicit --region or --output json: %s", l)
		}
	}
	// The HTTP:80 listener's redirect says HTTPS; it must not get a certificate call.
	if strings.Contains(string(log), "bbbb0003") {
		t.Error("the collector treated the HTTP listener (redirect to HTTPS) as a TLS listener")
	}

	var m struct {
		Kind  string `json:"kind"`
		Calls []struct {
			Operation  string `json:"operation"`
			ExitStatus int    `json:"exit_status"`
		} `json:"calls"`
	}
	b, err := os.ReadFile(filepath.Join(raw, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v\n%s", err, b)
	}
	if m.Kind != "hasr-aws-raw" || len(m.Calls) != 13 {
		t.Fatalf("manifest: kind %q, %d calls; want hasr-aws-raw, 13", m.Kind, len(m.Calls))
	}

	inv, err := aws.Convert(raw, cloud.Tool{Name: "hasr"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Scopes) != 1 || inv.Scopes[0].Status != cloud.ScopeRead {
		t.Errorf("scopes = %+v, want one read scope", inv.Scopes)
	}
	byPort := map[string]cloud.Endpoint{}
	for _, e := range inv.Endpoints {
		byPort[e.Name+":"+strconv.Itoa(e.Port)] = e
	}
	pq, def, plain := byPort["demo-pq:443"], byPort["demo-default:443"], byPort["demo-default:80"]
	if pq.TLS == nil || pq.TLS.KeyExchange != "hybrid" || pq.TLS.Legacy != "no" {
		t.Errorf("pq listener: %+v", pq.TLS)
	}
	if def.TLS == nil || def.TLS.KeyExchange != "classical" || def.TLS.Legacy != "yes" {
		t.Fatalf("default listener: %+v", def.TLS)
	}
	if got := strings.Join(def.TLS.Versions, ","); got != "TLS 1.0,TLS 1.1,TLS 1.2" {
		t.Errorf("default versions = %s", got)
	}
	reasons := strings.Join(def.TLS.LegacyReasons, "; ")
	for _, want := range []string{"TLS 1.0", "TLS 1.1", "RSA key transport", "AES128-GCM-SHA256", "AES128-SHA"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("default legacy reasons lack %q: %s", want, reasons)
		}
	}
	if strings.Contains(reasons, "ECDHE-RSA") {
		t.Errorf("an ECDHE suite was counted as RSA key transport: %s", reasons)
	}
	rec := def.TLS.Recommendation
	if rec == nil || !strings.Contains(rec.Action, "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09") || !strings.HasPrefix(rec.Links[0], "https://docs.aws.amazon.com/") {
		t.Fatalf("default recommendation = %+v", rec)
	}
	if got := strings.Join(rec.Effects, "; "); got != "adds hybrid post-quantum key exchange (ML-KEM); adds TLS 1.3; removes TLS 1.0, TLS 1.1; removes RSA key transport suites" {
		t.Errorf("effects = %s", got)
	}
	if pq.TLS.Recommendation != nil {
		t.Errorf("a PQ policy got a recommendation: %+v", pq.TLS.Recommendation)
	}
	if plain.TLS != nil || len(plain.Notes) == 0 {
		t.Errorf("HTTP listener: tls %+v notes %v", plain.TLS, plain.Notes)
	}
	if len(pq.TLS.Certificates) != 1 || pq.TLS.Certificates[0].Ref != ref || !pq.TLS.Certificates[0].Default {
		t.Errorf("pq certificate = %+v, want ref %s", pq.TLS.Certificates, ref)
	}
	if pq.Labels["owner"] != "Payments team (sample)" {
		t.Errorf("tags not carried: %v", pq.Labels)
	}
	if pq.Hostnames[0] != dnsPQ || pq.Exposure != "internet" {
		t.Errorf("pq hostnames %v exposure %s", pq.Hostnames, pq.Exposure)
	}
}

func TestCollectorRefusesRoot(t *testing.T) {
	fake, _ := fakeAWS(t, true)
	raw, code, out := runCollector(t, fake)
	if code != 4 {
		t.Fatalf("exit %d, want 4 (refused): %s", code, out)
	}
	log, _ := os.ReadFile(filepath.Join(fake, "invocations.log"))
	if strings.Contains(string(log), "elbv2") || strings.Contains(string(log), "acm") {
		t.Errorf("calls were made after the root check: %s", log)
	}
	if _, err := aws.Convert(raw, cloud.Tool{}, time.Now()); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("converting a refused collection: err = %v", err)
	}
}

func TestCollectorRecordsFailures(t *testing.T) {
	fake, _ := fakeAWS(t, false)
	if err := os.WriteFile(filepath.Join(fake, "acm_list-certificates.fail"),
		[]byte("An error occurred (AccessDeniedException) when calling the ListCertificates operation: denied\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, code, out := runCollector(t, fake)
	if code != 1 {
		t.Fatalf("exit %d, want 1 (some calls failed): %s", code, out)
	}
	inv, err := aws.Convert(raw, cloud.Tool{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := inv.Scopes[0]
	if s.Status != cloud.ScopePartial || !strings.Contains(strings.Join(s.Errors, " "), "AccessDeniedException") {
		t.Errorf("scope = %+v, want partial with the AccessDenied error", s)
	}
	if inv.Collection.FailedCalls != 1 {
		t.Errorf("failed calls = %d, want 1", inv.Collection.FailedCalls)
	}
}
