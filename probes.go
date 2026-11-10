package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

// Probe results.
const (
	resultAccepted = "accepted" // handshake completed
	resultRejected = "rejected" // the server sent a TLS alert (including close_notify before any ServerHello)
	// resultClosed: the server closed the connection after our ClientHello
	// without sending a byte, twice, while another probe on the same target
	// was accepted. Counted as a refusal (DECISIONS.md, "How a server refuses").
	resultClosed    = "closed"
	resultError     = "error"      // no answer: timeout, refused, reset, or an unexplained close
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
	// Stage says where an error happened: "tcp" (no TCP connection: timeout,
	// refused, unreachable) or "tls" (connected, then the TLS handshake failed,
	// e.g. the server closed the connection without an alert).
	Stage string `json:"stage,omitempty"`
	// BytesBeforeClose is the raw evidence when the handshake ended in EOF:
	// what the server sent before closing (first 16 bytes, hex) and how many.
	BytesBeforeClose *CloseEvidence `json:"bytes_before_close,omitempty"`

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
		st, stage, seen, err := handshake(spec.Config(), target, timeout)
		p.BytesBeforeClose = nil
		if err == nil {
			p.Result = resultAccepted
			p.Detail, p.Stage = "", ""
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
		p.Detail, p.Stage = describeError(stage, err), ""
		if isAlert(err) {
			p.Result = resultRejected
			return p, nil
		}
		if stage == stageTLS && errors.Is(err, io.EOF) {
			p.BytesBeforeClose = seen.evidence()
			switch {
			case seen.closeNotifyFirst():
				// RFC 8446 expects an alert with a reason here (e.g. protocol_version);
				// some servers (observed: AWS ALB) send close_notify instead. It is an
				// answer, so a refusal, but without a reason.
				p.Result, p.Detail = resultRejected, "closed with close_notify, no reason given"
				return p, nil
			case seen.total == 0:
				// Zero bytes, then FIN: retried; settleClosed decides after all probes.
				p.Result, p.Stage = resultClosed, stage
				p.Detail = closedZero
				continue
			}
		}
		p.Result, p.Stage = resultError, stage
		if !retryable(err) {
			return p, nil
		}
	}
	return p, nil
}

const closedZero = "closed after our ClientHello without sending a byte"

// settleClosed applies the rule for zero-byte closes once all probes of a
// target have run: "closed" counts as a refusal only if another probe on the
// same target was accepted; otherwise it is an error (the target may simply be
// dropping connections).
func settleClosed(probes []Probe) {
	accepted := false
	for _, p := range probes {
		if p.Result == resultAccepted {
			accepted = true
		}
	}
	if accepted {
		return
	}
	for i := range probes {
		if probes[i].Result == resultClosed {
			probes[i].Result = resultError
			// Keep the probe's note, which runProbe appended after the error text.
			probes[i].Detail = strings.Replace(probes[i].Detail, closedZero, closedZero+"; not counted as a refusal: no probe on this target was accepted", 1)
			probes[i].errText = strings.Replace(probes[i].errText, closedZero, closedZero+"; not counted as a refusal: no probe on this target was accepted", 1)
		}
	}
}

// CloseEvidence is what the server sent before closing the connection.
type CloseEvidence struct {
	Hex   string `json:"hex"`   // first bytes, at most 16
	Count int    `json:"count"` // all bytes received
}

// recorder keeps the first bytes the server sends on the raw TCP connection.
type recorder struct {
	net.Conn
	first []byte
	total int
}

const recordBytes = 16

func (r *recorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		if room := recordBytes - len(r.first); room > 0 {
			r.first = append(r.first, b[:min(n, room)]...)
		}
		r.total += n
	}
	return n, err
}

func (r *recorder) evidence() *CloseEvidence {
	return &CloseEvidence{Hex: hex.EncodeToString(r.first), Count: r.total}
}

// closeNotifyFirst: the first record is an alert (type 21) carrying
// close_notify (description 0), so nothing (no ServerHello) came before it.
func (r *recorder) closeNotifyFirst() bool {
	f := r.first
	return len(f) >= 7 && f[0] == 21 && f[1] == 3 && f[3] == 0 && f[4] == 2 && f[6] == 0
}

const (
	stageTCP = "tcp"
	stageTLS = "tls"
)

// handshake connects in two stages, so that silence at the TCP level is never
// mistaken for a TLS-level answer: first the TCP connection, then the TLS
// handshake on it. Each stage gets the full timeout. It returns the stage an
// error happened in.
func handshake(cfg *tls.Config, target string, timeout time.Duration) (tls.ConnectionState, string, *recorder, error) {
	// The probe observes what the server presents; it does not trust it and
	// sends it no data. Certificates are verified separately afterwards.
	cfg.InsecureSkipVerify = true
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(target); err == nil && net.ParseIP(host) == nil {
			cfg.ServerName = host
		}
	}
	dctx, dcancel := context.WithTimeout(context.Background(), timeout)
	defer dcancel()
	raw, err := (&net.Dialer{}).DialContext(dctx, "tcp", target)
	if err != nil {
		return tls.ConnectionState{}, stageTCP, &recorder{}, err
	}
	defer raw.Close()
	rec := &recorder{Conn: raw}
	hctx, hcancel := context.WithTimeout(context.Background(), timeout)
	defer hcancel()
	tc := tls.Client(rec, cfg)
	if err := tc.HandshakeContext(hctx); err != nil {
		return tls.ConnectionState{}, stageTLS, rec, err
	}
	return tc.ConnectionState(), "", rec, nil
}

// describeError words a failed attempt so the two stages read differently.
func describeError(stage string, err error) string {
	switch {
	case stage == stageTCP && retryable(err):
		return "no TCP connection: no answer to the connection attempt (timeout): " + err.Error()
	case stage == stageTCP:
		return "no TCP connection: " + err.Error()
	case errors.Is(err, io.EOF):
		return "TCP connected, then the server closed the connection during the TLS handshake without an alert (EOF)"
	case isAlert(err):
		return err.Error()
	}
	return "TLS handshake failed: " + err.Error()
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
