package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// Certificate is a leaf certificate a target presented, listed once per target.
type Certificate struct {
	Ref                string       `json:"ref"` // "sha256:<fingerprint of the DER>"
	Subject            string       `json:"subject"`
	Issuer             string       `json:"issuer"`
	NotBefore          time.Time    `json:"not_before"`
	NotAfter           time.Time    `json:"not_after"`
	PublicKey          PublicKey    `json:"public_key"`
	SignatureAlgorithm string       `json:"signature_algorithm"`
	Verification       Verification `json:"verification"`
}

type PublicKey struct {
	Algorithm string `json:"algorithm"`
	// Bits is omitted for key types this tool does not size yet.
	Bits  int    `json:"bits,omitempty"`
	Curve string `json:"curve,omitempty"`
}

// Verification holds three independent checks, so one failure doesn't hide another.
type Verification struct {
	ChainTrusted  bool   `json:"chain_trusted"`
	ChainError    string `json:"chain_error,omitempty"`
	HostnameMatch string `json:"hostname_match"` // match | mismatch | not_checked
	HostnameError string `json:"hostname_error,omitempty"`
	Validity      string `json:"validity"` // valid | expired | not_yet_valid
}

func certRef(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// describeCertificate describes chain[0] and verifies it, using the rest of
// the chain the server sent as intermediates. host is the target's host part.
func describeCertificate(chain []*x509.Certificate, host string, now time.Time) Certificate {
	leaf := chain[0]
	c := Certificate{
		Ref:                certRef(leaf),
		Subject:            leaf.Subject.String(),
		Issuer:             leaf.Issuer.String(),
		NotBefore:          leaf.NotBefore.UTC(),
		NotAfter:           leaf.NotAfter.UTC(),
		PublicKey:          describeKey(leaf),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
	}
	v := &c.Verification

	switch {
	case now.Before(leaf.NotBefore):
		v.Validity = "not_yet_valid"
	case now.After(leaf.NotAfter):
		v.Validity = "expired"
	default:
		v.Validity = "valid"
	}

	if net.ParseIP(host) != nil {
		v.HostnameMatch = "not_checked"
	} else if err := leaf.VerifyHostname(host); err != nil {
		v.HostnameMatch = "mismatch"
		v.HostnameError = err.Error()
	} else {
		v.HostnameMatch = "match"
	}

	// Judge trust at a moment inside the leaf's validity window, so an expired
	// leaf is reported under validity only and does not also fail the chain.
	at := now
	if v.Validity != "valid" {
		at = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	}
	inter := x509.NewCertPool()
	for _, ic := range chain[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: inter, CurrentTime: at}); err != nil {
		v.ChainError = err.Error()
	} else {
		v.ChainTrusted = true
	}
	return c
}

func describeKey(c *x509.Certificate) PublicKey {
	pk := PublicKey{Algorithm: c.PublicKeyAlgorithm.String()}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		pk.Bits = k.N.BitLen()
	case *ecdsa.PublicKey:
		pk.Bits = k.Curve.Params().BitSize
		pk.Curve = k.Curve.Params().Name
	case ed25519.PublicKey:
		pk.Bits = len(k) * 8
	}
	return pk
}

// keyLabel is a short human label such as "RSA 2048" or "ECDSA P-256".
func (pk PublicKey) keyLabel() string {
	switch {
	case pk.Curve != "":
		return pk.Algorithm + " " + pk.Curve
	case pk.Bits > 0:
		return fmt.Sprintf("%s %d", pk.Algorithm, pk.Bits)
	}
	return pk.Algorithm
}
