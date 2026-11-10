package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// readClientHello reads one whole TLS record, so closing afterwards sends a
// FIN, not an RST (a socket closed with unread data resets the connection).
func readClientHello(c net.Conn) error {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, binary.BigEndian.Uint16(h[3:5])))
	return err
}

// fakeServer runs handle for every connection on 127.0.0.1 and returns its address.
func fakeServer(t *testing.T, handle func(n int64, c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(i int64) { defer c.Close(); handle(i, c) }(n.Add(1))
		}
	}()
	return ln.Addr().String()
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func probe(t *testing.T, addr, id string) Probe {
	t.Helper()
	for i, spec := range probeSpecs {
		if spec.ID == id {
			p, _ := runProbe(spec, testOffers(t)[i], addr, 2*time.Second)
			return p
		}
	}
	t.Fatalf("no probe %s", id)
	return Probe{}
}

// What the AWS ALB sent on the wire: a 7-byte alert record, warning
// close_notify, then FIN. It is an answer: rejected, without a reason.
func TestCloseNotifyIsRejected(t *testing.T) {
	addr := fakeServer(t, func(_ int64, c net.Conn) {
		if readClientHello(c) == nil {
			c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00})
		}
	})
	p := probe(t, addr, "default")
	if p.Result != resultRejected || p.Detail != "closed with close_notify, no reason given" || p.Attempts != 1 {
		t.Errorf("result %s attempts %d detail %q", p.Result, p.Attempts, p.Detail)
	}
	if e := p.BytesBeforeClose; e == nil || e.Hex != "15030300020100" || e.Count != 7 {
		t.Errorf("evidence = %+v", e)
	}
}

// A fatal alert with a reason stays "rejected", as before.
func TestFatalAlertIsRejected(t *testing.T) {
	addr := fakeServer(t, func(_ int64, c net.Conn) {
		if readClientHello(c) == nil {
			c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 70}) // fatal protocol_version
		}
	})
	p := probe(t, addr, "default")
	if p.Result != resultRejected || !strings.Contains(p.Detail, "protocol version not supported") || p.BytesBeforeClose != nil {
		t.Errorf("result %s detail %q evidence %+v", p.Result, p.Detail, p.BytesBeforeClose)
	}
}

// Zero bytes then FIN, once: the retry completes the handshake.
func TestZeroByteCloseOnceThenAccepted(t *testing.T) {
	cfg := testTLSConfig(t)
	addr := fakeServer(t, func(n int64, c net.Conn) {
		if n == 1 {
			readClientHello(c)
			return
		}
		tls.Server(c, cfg).Handshake()
	})
	p := probe(t, addr, "default")
	if p.Result != resultAccepted || p.Attempts != 2 {
		t.Errorf("result %s attempts %d detail %q", p.Result, p.Attempts, p.Detail)
	}
}

// Zero bytes then FIN, every time, and no probe accepted: an error, never a refusal.
func TestZeroByteCloseEveryTimeIsError(t *testing.T) {
	addr := fakeServer(t, func(_ int64, c net.Conn) { readClientHello(c) })
	tg := scanTarget(addr, testOffers(t), 2*time.Second)
	for _, p := range tg.Probes {
		if p.Result == resultNotTested {
			continue
		}
		if p.Result != resultError || p.Attempts != 2 || !strings.Contains(p.Detail, "not counted as a refusal") ||
			p.BytesBeforeClose == nil || p.BytesBeforeClose.Count != 0 {
			t.Errorf("%s: result %s attempts %d detail %q evidence %+v", p.ID, p.Result, p.Attempts, p.Detail, p.BytesBeforeClose)
		}
	}
	if noTCP(tg) {
		t.Error("a TLS-level close was reported as no TCP connection")
	}
	if tg.Summary.Complete {
		t.Error("summary complete although every probe ended in error")
	}
}

// Zero bytes then FIN, every time, while another probe was accepted: a refusal.
func TestSettleClosed(t *testing.T) {
	ps := []Probe{acc("default", t13, aes13, x25519), {ID: "hybrid_only", Result: resultClosed, Detail: closedZero}}
	settleClosed(ps)
	if ps[1].Result != resultClosed {
		t.Errorf("with an accepted probe: %s", ps[1].Result)
	}
	// "closed" is conclusive: the hybrid probe was refused, so key exchange is classical.
	s := summarize(append(ps, acc("classical_only", t13, aes13, x25519), acc("max_tls12", t12, ecdhe, x25519),
		rej("tls11_only"), rej("tls10_only"), rej("tls12_weak")))
	if !s.Complete || s.KeyExchange != "classical" || s.Legacy != "no" {
		t.Errorf("summary with a closed probe: %+v", s)
	}
	ps = []Probe{{ID: "default", Result: resultRejected}, {ID: "hybrid_only", Result: resultClosed, Detail: closedZero + "; note"}}
	settleClosed(ps)
	if ps[1].Result != resultError || !strings.HasSuffix(ps[1].Detail, "; note") {
		t.Errorf("without an accepted probe: %s %q", ps[1].Result, ps[1].Detail)
	}
}
