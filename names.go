package main

import (
	"crypto/tls"
	"strings"
)

// Named is a TLS registry identifier: its IANA name plus its numeric codepoint.
type Named struct {
	Name      string `json:"name"`
	Codepoint uint16 `json:"codepoint"`
}

// ianaGroups maps TLS Supported Groups codepoints to their IANA registry names.
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
var ianaGroups = map[tls.CurveID]string{
	23:   "secp256r1",
	24:   "secp384r1",
	25:   "secp521r1",
	29:   "x25519",
	30:   "x448",
	256:  "ffdhe2048",
	257:  "ffdhe3072",
	258:  "ffdhe4096",
	259:  "ffdhe6144",
	260:  "ffdhe8192",
	512:  "MLKEM512",
	513:  "MLKEM768",
	514:  "MLKEM1024",
	4587: "SecP256r1MLKEM768",
	4588: "X25519MLKEM768",
	4589: "SecP384r1MLKEM1024",
}

// hybridGroups are the hybrid post-quantum key exchanges (classical ECDH + ML-KEM).
var hybridGroups = map[uint16]bool{
	uint16(tls.SecP256r1MLKEM768):  true,
	uint16(tls.X25519MLKEM768):     true,
	uint16(tls.SecP384r1MLKEM1024): true,
}

func groupName(id tls.CurveID) Named {
	name, ok := ianaGroups[id]
	if !ok {
		name = "unknown"
	}
	return Named{Name: name, Codepoint: uint16(id)}
}

// suiteName uses Go's cipher suite names, which are the IANA registry names.
func suiteName(id uint16) Named {
	return Named{Name: tls.CipherSuiteName(id), Codepoint: id}
}

// weakSuiteReason says why a cipher suite counts as weak, or returns "" if it
// does not. Weak means RSA key transport (no forward secrecy), 3DES, or RC4.
func weakSuiteReason(name string) string {
	var why []string
	if strings.HasPrefix(name, "TLS_RSA_WITH_") {
		why = append(why, "RSA key transport, no forward secrecy")
	}
	if strings.Contains(name, "_3DES_") {
		why = append(why, "3DES")
	}
	if strings.Contains(name, "_RC4_") {
		why = append(why, "RC4")
	}
	return strings.Join(why, ", ")
}
