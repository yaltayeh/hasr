package cloud

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func valid() Inventory {
	return Inventory{
		Kind: Kind, SchemaVersion: SchemaVersion, Provider: "aws",
		Scopes: []Scope{{Scope: "eu-north-1", Status: ScopeRead}},
		Endpoints: []Endpoint{{Provider: "aws", ResourceID: "id-1", Port: 443,
			TLS: &TLS{KeyExchange: "hybrid", Legacy: "no", KeyExchangeBasis: Basis{Links: []string{"https://docs.example/x"}}}}},
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid inventory rejected: %v", err)
	}
	cases := map[string]func(*Inventory){
		"kind":             func(i *Inventory) { i.Kind = "other" },
		"schema_version":   func(i *Inventory) { i.SchemaVersion = "9" },
		"provider":         func(i *Inventory) { i.Provider = "" },
		"status":           func(i *Inventory) { i.Scopes[0].Status = "ok" },
		"appears twice":    func(i *Inventory) { i.Endpoints = append(i.Endpoints, i.Endpoints[0]) },
		"port":             func(i *Inventory) { i.Endpoints[0].Port = 0 },
		"key_exchange":     func(i *Inventory) { i.Endpoints[0].TLS.KeyExchange = "pq" },
		"legacy":           func(i *Inventory) { i.Endpoints[0].TLS.Legacy = "maybe" },
		"https":            func(i *Inventory) { i.Endpoints[0].TLS.KeyExchangeBasis.Links = []string{"http://x"} },
		"in a \"aws\" inv": func(i *Inventory) { i.Endpoints[0].Provider = "gcp" },
	}
	for want, mutate := range cases {
		inv := valid()
		inv.Endpoints = append([]Endpoint{}, inv.Endpoints...)
		tl := *inv.Endpoints[0].TLS
		inv.Endpoints[0].TLS = &tl
		inv.Scopes = append([]Scope{}, inv.Scopes...)
		mutate(&inv)
		if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), strings.Split(want, " ")[0]) {
			t.Errorf("%s: err = %v", want, err)
		}
	}
}

func TestReadRejectsUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(p, []byte(`{"kind":"hasr-cloud","schema_version":"0.1","provider":"aws","surprise":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Errorf("err = %v, want unknown field", err)
	}
}
