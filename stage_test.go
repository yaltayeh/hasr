package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// A closed port: the TCP stage fails (refused), so the target is "no TCP connection".
func TestNoTCPConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	tg := scanTarget(addr, testOffers(t), 2*time.Second)
	for _, p := range tg.Probes {
		if p.Result == resultNotTested {
			continue
		}
		if p.Result != resultError || p.Stage != stageTCP || !strings.HasPrefix(p.Detail, "no TCP connection: ") {
			t.Errorf("%s: result %s stage %q detail %q", p.ID, p.Result, p.Stage, p.Detail)
		}
	}
	a := assessTarget(tg, &MappingEntry{Target: addr}, fullPolicy())
	if !strings.HasPrefix(a.Problem, "unreachable: no TCP connection (connection attempts failed") {
		t.Errorf("problem = %q", a.Problem)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Silence: every SYN unanswered. Tested on the wording, without sending
// packets to an address nobody authorised.
func TestSilenceWording(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
	d := describeError(stageTCP, err)
	if !strings.Contains(d, "no TCP connection: no answer to the connection attempt (timeout)") {
		t.Errorf("detail = %q", d)
	}
	tg := Target{Probes: []Probe{{ID: "default", Result: resultError, Stage: stageTCP, Detail: d + "; a note"}}}
	if !noTCP(tg) || tcpReason(tg) != "every connection attempt timed out: no answer at all" {
		t.Errorf("noTCP %v, reason %q", noTCP(tg), tcpReason(tg))
	}
	if describeError(stageTLS, errors.New("x")) != "TLS handshake failed: x" {
		t.Error("TLS-stage wording")
	}
}

func testOffers(t *testing.T) []*Offer {
	t.Helper()
	offers := make([]*Offer, len(probeSpecs))
	for i, spec := range probeSpecs {
		o, err := captureOffer(spec.Config())
		if err != nil {
			t.Fatal(err)
		}
		offers[i] = o
	}
	return offers
}
