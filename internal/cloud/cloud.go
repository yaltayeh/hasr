// Package cloud defines the provider-neutral inventory format that `hasr
// report --cloud` reads. Each provider (internal/cloud/aws today) converts its
// own raw data into this format; the report never sees provider-specific data
// or rules, only verdicts with their basis (DECISIONS.md, "Cloud discovery").
//
// The vocabulary matches the scan's: key_exchange is hybrid | classical |
// unknown, legacy is yes | no | unknown, versions are "TLS 1.2" style, and a
// certificate ref is "sha256:<fingerprint of the DER>".
package cloud

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	Kind          = "hasr-cloud"
	SchemaVersion = "0.1"
)

// Inventory is one provider run: everything one collector folder held.
type Inventory struct {
	Kind          string     `json:"kind"`
	SchemaVersion string     `json:"schema_version"`
	Tool          Tool       `json:"tool"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Provider      string     `json:"provider"` // "aws"
	Collection    Collection `json:"collection"`
	// Scopes are the units the provider was asked to read (AWS: account and region).
	Scopes []Scope `json:"scopes"`
	// ResourceTypesRead lists what was read; anything else was not.
	ResourceTypesRead []string `json:"resource_types_read"`
	// NotRead are stated limits: what this provider does not cover.
	NotRead   []Limit    `json:"not_read"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Tool struct {
	Name string `json:"name"`
	Go   string `json:"go"`
}

// Collection describes the raw evidence the inventory was converted from.
type Collection struct {
	Collector        string    `json:"collector"` // e.g. "collectors/aws/collect.sh 0.1"
	CollectorVersion string    `json:"collector_version"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	Calls            int       `json:"calls"`
	FailedCalls      int       `json:"failed_calls"`
}

type Scope struct {
	Scope  string   `json:"scope"`  // e.g. "eu-north-1"
	Status string   `json:"status"` // read | partial | failed
	Errors []string `json:"errors,omitempty"`
}

const (
	ScopeRead    = "read"
	ScopePartial = "partial"
	ScopeFailed  = "failed"
)

type Limit struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// Endpoint is one network endpoint the provider knows of, such as a load
// balancer listener.
type Endpoint struct {
	Provider     string `json:"provider"`
	Scope        string `json:"scope"`
	ResourceID   string `json:"resource_id"`   // provider's identifier (AWS: listener ARN)
	ResourceKind string `json:"resource_kind"` // e.g. "load_balancer_listener"
	Name         string `json:"name"`          // human name (AWS: load balancer name)
	// Hostnames the endpoint answers to; the report matches scan targets against them.
	Hostnames []string `json:"hostnames"`
	Port      int      `json:"port"`
	Protocol  string   `json:"protocol"` // as the provider names it, e.g. HTTPS, TLS, HTTP
	Exposure  string   `json:"exposure"` // internet | internal | unknown
	// TLS is nil when the endpoint does not terminate TLS itself.
	TLS *TLS `json:"tls"`
	// Labels are the provider's tags, as found.
	Labels map[string]string `json:"labels"`
	Notes  []string          `json:"notes,omitempty"`
}

type TLS struct {
	Policy             Policy        `json:"policy"`
	Versions           []string      `json:"versions"` // [] = unknown
	KeyExchange        string        `json:"key_exchange"`
	KeyExchangeReasons []string      `json:"key_exchange_reasons"`
	KeyExchangeBasis   Basis         `json:"key_exchange_basis"`
	Legacy             string        `json:"legacy"`
	LegacyReasons      []string      `json:"legacy_reasons"`
	Certificates       []Certificate `json:"certificates"`
	// Recommendation is the provider's recommended change, when the endpoint
	// lacks hybrid key exchange; nil otherwise.
	Recommendation *Recommendation `json:"recommendation,omitempty"`
}

// Recommendation is a provider-specific action, worded by the provider, with
// its source and what the change does compared with the current policy.
type Recommendation struct {
	Action  string   `json:"action"`
	Links   []string `json:"links"`
	Effects []string `json:"effects"` // e.g. "adds TLS 1.3", "removes RSA key transport suites"
}

type Policy struct {
	Name string `json:"name"`
	// Managed: a predefined policy the provider maintains, switched by setting
	// a name on the endpoint (Clause 2b evidence: changeable in place).
	Managed bool `json:"managed"`
	// ContentsKnown is false when the policy's protocols and ciphers could not be read.
	ContentsKnown bool `json:"contents_known"`
}

// Basis says what a verdict rests on, with links to the provider's documentation.
type Basis struct {
	Rule  string   `json:"rule"`
	Links []string `json:"links"`
}

type Certificate struct {
	Ref          string    `json:"ref,omitempty"` // empty when the certificate body could not be read
	ResourceID   string    `json:"resource_id"`
	Default      bool      `json:"default"` // the listener's default certificate (others are SNI)
	Subject      string    `json:"subject,omitempty"`
	Serial       string    `json:"serial,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm,omitempty"` // provider's name, e.g. RSA_2048
	NotAfter     time.Time `json:"not_after,omitzero"`
	Origin       string    `json:"origin,omitempty"` // e.g. IMPORTED, AMAZON_ISSUED
}

// Read loads and validates an inventory file.
func Read(path string) (Inventory, error) {
	f, err := os.Open(path)
	if err != nil {
		return Inventory{}, err
	}
	defer f.Close()
	var inv Inventory
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return Inventory{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := inv.Validate(); err != nil {
		return Inventory{}, fmt.Errorf("%s: %w", path, err)
	}
	return inv, nil
}

// Validate checks the fields the report relies on.
func (inv Inventory) Validate() error {
	if inv.Kind != Kind {
		return fmt.Errorf("kind is %q, want %q", inv.Kind, Kind)
	}
	if inv.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version %q, this hasr reads %q; re-run the converter", inv.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(inv.Provider) == "" {
		return errors.New("provider is empty")
	}
	for _, s := range inv.Scopes {
		if !oneOf(s.Status, ScopeRead, ScopePartial, ScopeFailed) {
			return fmt.Errorf("scope %q: status %q", s.Scope, s.Status)
		}
	}
	seen := map[string]bool{}
	for _, e := range inv.Endpoints {
		if e.ResourceID == "" {
			return errors.New("an endpoint has no resource_id")
		}
		if seen[e.ResourceID] {
			return fmt.Errorf("endpoint %s appears twice", e.ResourceID)
		}
		seen[e.ResourceID] = true
		if e.Provider != inv.Provider {
			return fmt.Errorf("endpoint %s: provider %q in a %q inventory", e.ResourceID, e.Provider, inv.Provider)
		}
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("endpoint %s: port %d", e.ResourceID, e.Port)
		}
		if t := e.TLS; t != nil {
			if !oneOf(t.KeyExchange, "hybrid", "classical", "unknown") {
				return fmt.Errorf("endpoint %s: key_exchange %q", e.ResourceID, t.KeyExchange)
			}
			if !oneOf(t.Legacy, "yes", "no", "unknown") {
				return fmt.Errorf("endpoint %s: legacy %q", e.ResourceID, t.Legacy)
			}
			links := append([]string{}, t.KeyExchangeBasis.Links...)
			if t.Recommendation != nil {
				links = append(links, t.Recommendation.Links...)
			}
			for _, l := range links {
				if u, err := url.Parse(l); err != nil || u.Scheme != "https" || u.Host == "" {
					return fmt.Errorf("endpoint %s: basis link %q must be an absolute https URL", e.ResourceID, l)
				}
			}
		}
	}
	return nil
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}
