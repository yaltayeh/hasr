package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// Probe results.
const (
	resultAccepted  = "accepted"   // handshake completed
	resultRejected  = "rejected"   // the server sent a TLS alert
	resultError     = "error"      // no answer: timeout, refused, reset, closed without an alert
	resultNotTested = "not_tested" // Go cannot test this; never read as "not supported"
)

// Probe is one handshake attempt with a specific offer, or a not_tested entry.
type Probe struct {
	ID         string      `json:"id"`
	Offered    *Offer      `json:"offered,omitempty"`
	Result     string      `json:"result"`
	Attempts   int         `json:"attempts,omitempty"`
	Negotiated *Negotiated `json:"negotiated,omitempty"`
	Detail     string      `json:"detail,omitempty"` // error text, then the probe's note

	// Kept apart for the table, which prints each note once instead of per probe.
	errText string
	note    string
}

// Offer is what the probe's ClientHello actually carried.
type Offer struct {
	Versions     []string `json:"versions"`
	Groups       []Named  `json:"groups"`
	CipherSuites []Named  `json:"cipher_suites"`
}

// Negotiated is what the server chose from the offer.
type Negotiated struct {
	Version     string `json:"version"`
	CipherSuite Named  `json:"cipher_suite"`
	// Group is absent when no group was used (RSA key transport).
	Group          *Named `json:"group,omitempty"`
	CertificateRef string `json:"certificate_ref,omitempty"`

	version uint16 // numeric version, for classification
}

type probeSpec struct {
	ID     string
	Config func() *tls.Config
	// Note is added to the probe's detail field whatever the result.
	Note string
}

// unverifiedNote marks probes whose offer includes suites never verified in a
// full handshake against a test server (DECISIONS.md, "Legacy probe offers").
const unverifiedNote = "3DES and RC4 suites offered; handshakes using them not yet verified against a test server"

// probeSpecs are the step-2 probes, in the order they run (DECISIONS.md, "Step 2 probes").
var probeSpecs = []probeSpec{
	{"default", func() *tls.Config { return &tls.Config{} }, ""},
	{"hybrid_only", func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	}, ""},
	{"classical_only", func() *tls.Config {
		return &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}}
	}, ""},
	{"max_tls12", func() *tls.Config { return &tls.Config{MaxVersion: tls.VersionTLS12} }, ""},
	{"tls11_only", func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11, CipherSuites: allGoSuites()}
	}, unverifiedNote},
	{"tls10_only", func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, CipherSuites: allGoSuites()}
	}, unverifiedNote},
	{"tls12_weak", func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: weakGoSuites()}
	}, unverifiedNote},
}

// notTested lists what Go's crypto/tls cannot test. Each becomes a not_tested probe entry.
var notTested = []Probe{
	{ID: "ssl3", Result: resultNotTested, Detail: "Go crypto/tls does not implement SSL 3.0"},
	{ID: "ffdhe", Result: resultNotTested, Detail: "Go crypto/tls does not implement finite-field DHE (TLS_DHE_* suites, ffdhe groups)"},
	{ID: "other_groups", Result: resultNotTested, Detail: "only groups in some probe's offer were tested; others (e.g. x448, brainpool curves, pure ML-KEM) were not"},
	{ID: "handshake_signature_scheme", Result: resultNotTested, Detail: "Go crypto/tls does not report the signature scheme the server used in the handshake"},
}

// allGoSuites returns every cipher suite Go implements, secure and insecure.
// Go filters the list by protocol version when it builds the ClientHello.
func allGoSuites() []uint16 {
	var ids []uint16
	for _, cs := range tls.CipherSuites() {
		ids = append(ids, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		ids = append(ids, cs.ID)
	}
	return ids
}

// weakGoSuites returns the suites Go implements that use RSA key transport, 3DES or RC4.
func weakGoSuites() []uint16 {
	var ids []uint16
	for _, cs := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if weakSuiteReason(cs.Name) != "" {
			ids = append(ids, cs.ID)
		}
	}
	return ids
}

// captureOffer records the ClientHello a config really sends, by handshaking
// with an in-memory recorder that aborts once it has read the ClientHello.
// Nothing goes on the network.
func captureOffer(cfg *tls.Config) (*Offer, error) {
	client, server := net.Pipe()
	defer client.Close()
	got := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		defer server.Close()
		tls.Server(server, &tls.Config{GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			got <- chi
			return nil, errors.New("offer captured")
		}}).Handshake()
	}()
	cfg.InsecureSkipVerify = true
	cfg.ServerName = "offer.invalid"
	client.SetDeadline(time.Now().Add(5 * time.Second))
	tls.Client(client, cfg).Handshake()

	var chi *tls.ClientHelloInfo
	select {
	case chi = <-got:
	case <-time.After(5 * time.Second):
		return nil, errors.New("no ClientHello captured")
	}
	o := &Offer{Versions: []string{}, Groups: []Named{}, CipherSuites: []Named{}}
	for _, v := range chi.SupportedVersions {
		o.Versions = append(o.Versions, tls.VersionName(v))
	}
	for _, g := range chi.SupportedCurves {
		o.Groups = append(o.Groups, groupName(g))
	}
	for _, s := range chi.CipherSuites {
		o.CipherSuites = append(o.CipherSuites, suiteName(s))
	}
	return o, nil
}

// runProbe performs the probe's handshake, retrying once on timeout or reset.
// On success it also returns the certificates the server sent.
func runProbe(spec probeSpec, offer *Offer, target string, timeout time.Duration) (Probe, []*x509.Certificate) {
	p, chain := attemptProbe(spec, offer, target, timeout)
	p.errText, p.note = p.Detail, spec.Note
	if spec.Note != "" {
		if p.Detail != "" {
			p.Detail += "; "
		}
		p.Detail += spec.Note
	}
	return p, chain
}

func attemptProbe(spec probeSpec, offer *Offer, target string, timeout time.Duration) (Probe, []*x509.Certificate) {
	p := Probe{ID: spec.ID, Offered: offer}
	for attempt := 1; attempt <= 2; attempt++ {
		p.Attempts = attempt
		st, err := handshake(spec.Config(), target, timeout)
		if err == nil {
			p.Result = resultAccepted
			p.Detail = ""
			p.Negotiated = &Negotiated{
				Version:     tls.VersionName(st.Version),
				CipherSuite: suiteName(st.CipherSuite),
				version:     st.Version,
			}
			if st.CurveID != 0 {
				g := groupName(st.CurveID)
				p.Negotiated.Group = &g
			}
			return p, st.PeerCertificates
		}
		p.Detail = err.Error()
		if isAlert(err) {
			p.Result = resultRejected
			return p, nil
		}
		p.Result = resultError
		if !retryable(err) {
			return p, nil
		}
	}
	return p, nil
}

func handshake(cfg *tls.Config, target string, timeout time.Duration) (tls.ConnectionState, error) {
	// The probe observes what the server presents; it does not trust it and
	// sends it no data. Certificates are verified separately afterwards.
	cfg.InsecureSkipVerify = true
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", target)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, fmt.Errorf("unexpected connection type %T", conn)
	}
	return tc.ConnectionState(), nil
}

// isAlert reports whether the server answered with a TLS alert.
// Go reports a received alert as a *net.OpError with Op "remote error".
func isAlert(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "remote error"
}

// retryable reports a timeout or a connection reset.
func retryable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
