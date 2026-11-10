package aws

import "testing"

func TestWeakCipher(t *testing.T) {
	cases := map[string]string{
		"TLS_AES_128_GCM_SHA256":        "",
		"ECDHE-ECDSA-AES128-GCM-SHA256": "",
		"ECDHE-RSA-AES256-SHA384":       "",
		"DHE-RSA-AES128-SHA":            "",
		"AES128-GCM-SHA256":             "rsa",
		"AES256-SHA":                    "rsa",
		"DES-CBC3-SHA":                  "3des",
		"ECDHE-RSA-DES-CBC3-SHA":        "3des",
		"RC4-SHA":                       "rc4",
	}
	for name, want := range cases {
		if got := weakCipher(name); got != want {
			t.Errorf("weakCipher(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestTLSInfo(t *testing.T) {
	pols := map[string]sslPolicy{"P-2016": {Name: "P-2016", SslProtocols: []string{"TLSv1", "TLSv1.2"}}}
	if got := tlsInfo("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", pols, "application"); got.KeyExchange != "hybrid" || got.Legacy != "unknown" || got.Policy.ContentsKnown {
		t.Errorf("PQ policy without contents: %+v", got)
	}
	got := tlsInfo("P-2016", pols, "network")
	if got.KeyExchange != "classical" || got.Legacy != "yes" || got.KeyExchangeBasis.Links[0] != docNLBPolicies {
		t.Errorf("classical policy: %+v", got)
	}
	if got := tlsInfo("", pols, "application"); got.KeyExchange != "unknown" {
		t.Errorf("no policy name: %+v", got)
	}
}
