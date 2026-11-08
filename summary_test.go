package main

import (
	"crypto/tls"
	"reflect"
	"testing"
)

// acc builds an accepted probe with the given negotiated version, suite and group.
func acc(id string, ver uint16, suite uint16, group tls.CurveID) Probe {
	n := &Negotiated{Version: tls.VersionName(ver), CipherSuite: suiteName(suite), version: ver}
	if group != 0 {
		g := groupName(group)
		n.Group = &g
	}
	return Probe{ID: id, Result: resultAccepted, Negotiated: n}
}

func rej(id string) Probe { return Probe{ID: id, Result: resultRejected} }
func er(id string) Probe  { return Probe{ID: id, Result: resultError} }

const (
	aes13  = tls.TLS_AES_128_GCM_SHA256
	ecdhe  = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	cbc    = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	rsaKex = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	tdes   = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
	t10    = tls.VersionTLS10
	t11    = tls.VersionTLS11
	t12    = tls.VersionTLS12
	t13    = tls.VersionTLS13
	mlkem  = tls.X25519MLKEM768
	x25519 = tls.X25519
)

func TestSummarize(t *testing.T) {
	tests := []struct {
		name          string
		probes        []Probe
		kex           string
		kexReasons    []string
		legacy        string
		legacyReasons []string
		complete      bool
	}{
		{
			name: "server a: hybrid, no legacy",
			probes: []Probe{acc("default", t13, aes13, mlkem), acc("hybrid_only", t13, aes13, mlkem),
				acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
				rej("tls11_only"), rej("tls10_only"), rej("tls12_weak")},
			kex: "hybrid", kexReasons: []string{"hybrid group negotiated: X25519MLKEM768"},
			legacy: "no", legacyReasons: []string{}, complete: true,
		},
		{
			name: "server b: classical, no legacy",
			probes: []Probe{acc("default", t13, aes13, x25519), rej("hybrid_only"),
				acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
				rej("tls11_only"), rej("tls10_only"), rej("tls12_weak")},
			kex: "classical", kexReasons: []string{"no hybrid group negotiated"},
			legacy: "no", legacyReasons: []string{}, complete: true,
		},
		{
			name: "TLS 1.2 max, nothing older: classical with upgrade reason, not legacy",
			probes: []Probe{acc("default", t12, ecdhe, x25519), rej("hybrid_only"),
				acc("classical_only", t12, ecdhe, x25519), acc("max_tls12", t12, ecdhe, x25519),
				rej("tls11_only"), rej("tls10_only"), rej("tls12_weak")},
			kex: "classical", kexReasons: []string{"no hybrid group negotiated", noTLS13Reason},
			legacy: "no", legacyReasons: []string{}, complete: true,
		},
		{
			name: "server c: classical, no TLS 1.3, legacy versions and RSA key transport",
			probes: []Probe{acc("default", t12, ecdhe, x25519), rej("hybrid_only"),
				acc("classical_only", t12, ecdhe, x25519), acc("max_tls12", t12, ecdhe, x25519),
				acc("tls11_only", t11, cbc, x25519), acc("tls10_only", t10, cbc, x25519), acc("tls12_weak", t12, rsaKex, 0)},
			kex: "classical", kexReasons: []string{"no hybrid group negotiated", noTLS13Reason},
			legacy: "yes", legacyReasons: []string{"accepts TLS 1.0", "accepts TLS 1.1",
				"weak suite accepted: TLS_RSA_WITH_AES_128_GCM_SHA256 (RSA key transport, no forward secrecy)"},
			complete: true,
		},
		{
			name: "hybrid and legacy at once: both fields set independently",
			probes: []Probe{acc("default", t13, aes13, mlkem), acc("hybrid_only", t13, aes13, mlkem),
				acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
				acc("tls11_only", t11, cbc, x25519), acc("tls10_only", t10, cbc, x25519), acc("tls12_weak", t12, tdes, 0)},
			kex: "hybrid", kexReasons: []string{"hybrid group negotiated: X25519MLKEM768"},
			legacy: "yes", legacyReasons: []string{"accepts TLS 1.0", "accepts TLS 1.1",
				"weak suite accepted: TLS_RSA_WITH_3DES_EDE_CBC_SHA (RSA key transport, no forward secrecy, 3DES)"},
			complete: true,
		},
		{
			name: "unreachable: everything errored",
			probes: []Probe{er("default"), er("hybrid_only"), er("classical_only"), er("max_tls12"),
				er("tls11_only"), er("tls10_only"), er("tls12_weak")},
			kex: "unknown", kexReasons: []string{"no probe accepted"},
			legacy: "unknown", legacyReasons: []string{}, complete: false,
		},
		{
			name: "hybrid_only errored: classical not proven",
			probes: []Probe{acc("default", t13, aes13, x25519), er("hybrid_only"),
				acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
				rej("tls11_only"), rej("tls10_only"), rej("tls12_weak")},
			kex: "unknown", kexReasons: []string{"inconclusive: a probe that offers a hybrid group ended in error"},
			legacy: "no", legacyReasons: []string{}, complete: false,
		},
		{
			name: "classical_only errored: no 'no TLS 1.3' claim",
			probes: []Probe{acc("default", t12, ecdhe, x25519), rej("hybrid_only"),
				er("classical_only"), acc("max_tls12", t12, ecdhe, x25519),
				rej("tls11_only"), rej("tls10_only"), rej("tls12_weak")},
			kex: "classical", kexReasons: []string{"no hybrid group negotiated"},
			legacy: "no", legacyReasons: []string{}, complete: false,
		},
		{
			name: "hybrid found despite errors elsewhere: positive evidence stands",
			probes: []Probe{acc("default", t13, aes13, mlkem), er("hybrid_only"),
				er("classical_only"), er("max_tls12"), er("tls11_only"), er("tls10_only"), er("tls12_weak")},
			kex: "hybrid", kexReasons: []string{"hybrid group negotiated: X25519MLKEM768"},
			legacy: "unknown", legacyReasons: []string{}, complete: false,
		},
		{
			name: "only tls10_only errored: legacy not cleared",
			probes: []Probe{acc("default", t13, aes13, x25519), rej("hybrid_only"),
				acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
				rej("tls11_only"), er("tls10_only"), rej("tls12_weak")},
			kex: "classical", kexReasons: []string{"no hybrid group negotiated"},
			legacy: "unknown", legacyReasons: []string{}, complete: false,
		},
		{
			name: "legacy finding stands despite a legacy probe error",
			probes: []Probe{acc("default", t13, aes13, x25519), rej("hybrid_only"),
				acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
				acc("tls11_only", t11, cbc, x25519), er("tls10_only"), rej("tls12_weak")},
			kex: "classical", kexReasons: []string{"no hybrid group negotiated"},
			legacy: "yes", legacyReasons: []string{"accepts TLS 1.1"}, complete: false,
		},
		{
			name:   "no probes at all",
			probes: nil,
			kex:    "unknown", kexReasons: []string{"no probe accepted"},
			legacy: "unknown", legacyReasons: []string{}, complete: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := summarize(tc.probes)
			if s.KeyExchange != tc.kex || !reflect.DeepEqual(s.KeyExchangeReasons, tc.kexReasons) {
				t.Errorf("key_exchange = %q %q, want %q %q", s.KeyExchange, s.KeyExchangeReasons, tc.kex, tc.kexReasons)
			}
			if s.Legacy != tc.legacy || !reflect.DeepEqual(s.LegacyReasons, tc.legacyReasons) {
				t.Errorf("legacy = %q %q, want %q %q", s.Legacy, s.LegacyReasons, tc.legacy, tc.legacyReasons)
			}
			if s.Complete != tc.complete {
				t.Errorf("complete = %v, want %v", s.Complete, tc.complete)
			}
		})
	}
}
