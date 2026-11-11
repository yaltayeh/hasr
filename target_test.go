package main

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCanonicalTarget(t *testing.T) {
	good := []struct {
		in          string
		defaultPort bool
		want        string
	}{
		{"bank.sa:443", false, "bank.sa:443"},
		{"BANK.SA.:443", false, "bank.sa:443"},
		{" Bank.Sa:8443 ", false, "bank.sa:8443"},
		{"bank.sa:0443", false, "bank.sa:443"},
		{"bank.sa:1", false, "bank.sa:1"},
		{"bank.sa:65535", false, "bank.sa:65535"},
		{"10.0.0.1:443", false, "10.0.0.1:443"},
		{"[10.0.0.1]:443", false, "10.0.0.1:443"},
		{"[::1]:443", false, "[::1]:443"},
		{"[2001:DB8:0:0::1]:8443", false, "[2001:db8::1]:8443"},
		{"[fe80::1%en0]:443", false, "[fe80::1%en0]:443"},
		// Command line only: no port means :443.
		{"bank.sa", true, "bank.sa:443"},
		{"BANK.SA.", true, "bank.sa:443"},
		{"10.0.0.1", true, "10.0.0.1:443"},
		{"::1", true, "[::1]:443"},
		{"[::1]", true, "[::1]:443"},
		{"bank.sa:8443", true, "bank.sa:8443"},
	}
	for _, tc := range good {
		got, err := canonicalTarget(tc.in, tc.defaultPort)
		if err != nil || got != tc.want {
			t.Errorf("canonicalTarget(%q, %v) = %q, %v; want %q", tc.in, tc.defaultPort, got, err, tc.want)
		}
	}

	bad := []struct {
		in          string
		defaultPort bool
		want        string
	}{
		{"bank.sa:", false, "empty port"},
		{"bank.sa:", true, "empty port"}, // an explicit empty port is not "no port"
		{"bank.sa:https", false, "not a number (service names are not accepted)"},
		{"bank.sa:https", true, "not a number"},
		{"bank.sa:99999", false, "outside 1-65535"},
		{"bank.sa:0", false, "outside 1-65535"},
		{"bank.sa:+443", false, "not a number"},
		{"bank.sa:-1", false, "not a number"},
		{"bank.sa", false, "must be host:port"}, // the CSV needs an explicit port
		{"::1", false, "must be host:port"},     // so does an IPv6 address
		{"::1:443", false, "must be host:port"}, // IPv6 with a port needs brackets
		{":443", false, "has no host"},
		{".:443", false, "has no host"},
		{"", true, "empty target"},
		{"https://bank.sa:443", false, "is a URL; give host:port"},
		{"https://bank.sa", true, "is a URL"},
		{"bank.sa/login:443", false, `host contains '/'`},
		{"bank.sa:443:443", false, "must be host:port"},
	}
	for _, tc := range bad {
		_, err := canonicalTarget(tc.in, tc.defaultPort)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("canonicalTarget(%q, %v) error = %v; want it to contain %q", tc.in, tc.defaultPort, err, tc.want)
		}
	}
}

// A command-line target and a CSV row written differently are the same asset.
func TestCanonicalTargetJoin(t *testing.T) {
	cli, err := canonicalTarget("bank.sa:443", true)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := parseMapping(strings.NewReader(header+"BANK.SA.:443,Portal,,,Secret,,,in-house,\n"), ndmoPolicy().labels())
	if err != nil {
		t.Fatal(err)
	}
	if mapping[0].Target != "bank.sa:443" {
		t.Fatalf("CSV target = %q, want bank.sa:443", mapping[0].Target)
	}
	scan := Report{SchemaVersion: schemaVersion, Targets: []Target{classical13(cli)}}
	r := buildReport(scan, Inputs{}, mapping, fullPolicy(), time.Unix(0, 0))
	if len(r.Assets) != 1 || len(r.NeedsOwnerInput) != 0 || len(r.MappedNotScanned) != 0 {
		t.Errorf("assets %d, needs owner input %d, mapped not scanned %d; want 1, 0, 0",
			len(r.Assets), len(r.NeedsOwnerInput), len(r.MappedNotScanned))
	}

	// Two rows that differ only in form are duplicates.
	_, err = parseMapping(strings.NewReader(header+"bank.sa:443,a,,,,,,,\nBANK.SA.:443,b,,,,,,,\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "target bank.sa:443 is already on line 2") {
		t.Errorf("duplicate in another form: err = %v", err)
	}
}

// An invalid command-line target stops the scan before anything is sent.
func TestRunScanRejectsInvalidTarget(t *testing.T) {
	for _, arg := range []string{"bank.sa:", "bank.sa:https", "bank.sa:99999"} {
		if code := runScan([]string{arg}); code != 2 {
			t.Errorf("runScan(%q) = %d, want 2", arg, code)
		}
	}
}

// The probe dials the full host:port, and sends SNI with the host alone, or
// none for an IP address.
func TestHandshakeAddressAndSNI(t *testing.T) {
	cases := []struct {
		network, listen, host, wantSNI string
	}{
		{"tcp4", "127.0.0.1:0", "localhost", "localhost"},
		{"tcp4", "127.0.0.1:0", "127.0.0.1", ""},
		{"tcp6", "[::1]:0", "::1", ""},
	}
	for _, tc := range cases {
		ln, err := net.Listen(tc.network, tc.listen)
		if err != nil {
			t.Logf("%s: %v (skipped)", tc.listen, err)
			continue
		}
		got := make(chan string, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			tls.Server(c, &tls.Config{GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				got <- chi.ServerName
				return nil, errors.New("captured")
			}}).Handshake()
		}()
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		target := net.JoinHostPort(tc.host, port) // a random port: only the full host:port reaches it
		handshake(probeSpecs[0].Config(), target, 2*time.Second)
		ln.Close()
		select {
		case sni := <-got:
			if sni != tc.wantSNI {
				t.Errorf("%s: SNI %q, want %q", target, sni, tc.wantSNI)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s: the server saw no ClientHello", target)
		}
	}
}
