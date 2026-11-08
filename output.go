package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

func printJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// printTable writes one summary row per target, then a detail block per target.
func printTable(w io.Writer, r Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tKEX\tLEGACY\tVERSIONS\tDEFAULT GETS\tCERT KEYS\tTRUSTED")
	incomplete := false
	for _, t := range r.Targets {
		name := t.Target
		if !t.Summary.Complete {
			name += " *"
			incomplete = true
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, t.Summary.KeyExchange, legacyMark(t.Summary.Legacy),
			dash(shortVersions(t.Summary.VersionsAccepted)), defaultGets(t), dash(certKeys(t)), trusted(t))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if incomplete {
		fmt.Fprintln(w, "* incomplete: some probes ended in error; see the detail block")
	}
	printNotes(w, r)
	for _, t := range r.Targets {
		if err := printDetail(w, t); err != nil {
			return err
		}
	}
	return nil
}

func printDetail(w io.Writer, t Target) error {
	s := t.Summary
	fmt.Fprintf(w, "\n%s\n", t.Target)
	if t.Error != "" {
		_, err := fmt.Fprintf(w, "  ERROR: %s\n", t.Error)
		return err
	}
	fmt.Fprintf(w, "  key exchange  %s: %s\n", s.KeyExchange, strings.Join(s.KeyExchangeReasons, "; "))
	switch s.Legacy {
	case "yes":
		fmt.Fprintf(w, "  legacy        yes: %s\n", strings.Join(s.LegacyReasons, "; "))
	case "unknown":
		fmt.Fprintf(w, "  legacy        unknown: a legacy probe gave no answer\n")
	default:
		fmt.Fprintf(w, "  legacy        %s\n", s.Legacy)
	}
	if !s.Complete {
		fmt.Fprintf(w, "  incomplete    inconclusive probes: %s\n", strings.Join(s.InconclusiveProbes, ", "))
	}
	fmt.Fprintln(w)

	labels := map[string]string{}
	for _, c := range t.Certificates {
		labels[c.Ref] = c.PublicKey.keyLabel() + " [" + shortRef(c.Ref) + "]"
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  PROBE\tRESULT\tVERSION\tCIPHER SUITE\tGROUP\tCERT\tDETAIL")
	var skipped []string
	for _, p := range t.Probes {
		if p.Result == resultNotTested {
			skipped = append(skipped, p.ID)
			continue
		}
		detail := p.errText // the note, if any, is printed once under the summary table
		if p.Attempts > 1 {
			detail = fmt.Sprintf("(%d attempts) %s", p.Attempts, detail)
		}
		if n := p.Negotiated; n != nil {
			group := "-"
			if n.Group != nil {
				group = n.Group.Name
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.Result, n.Version, n.CipherSuite.Name, group, dash(labels[n.CertificateRef]), detail)
		} else {
			fmt.Fprintf(tw, "  %s\t%s\t-\t-\t-\t-\t%s\n", p.ID, p.Result, detail)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(skipped) > 0 {
		fmt.Fprintf(w, "  not tested: %s\n", strings.Join(skipped, ", "))
	}
	if len(t.Certificates) == 0 {
		return nil
	}

	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  CERTIFICATE\tKEY\tSIGNATURE\tCHAIN\tHOSTNAME\tVALIDITY\tNOT AFTER\tSUBJECT")
	for _, c := range t.Certificates {
		v := c.Verification
		chain := "trusted"
		if !v.ChainTrusted {
			chain = "not trusted"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", shortRef(c.Ref), c.PublicKey.keyLabel(), c.SignatureAlgorithm,
			chain, v.HostnameMatch, v.Validity, c.NotAfter.Format("2006-01-02"), c.Subject)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, c := range t.Certificates {
		if c.Verification.ChainError != "" {
			fmt.Fprintf(w, "  %s chain: %s\n", shortRef(c.Ref), c.Verification.ChainError)
		}
		if c.Verification.HostnameError != "" {
			fmt.Fprintf(w, "  %s hostname: %s\n", shortRef(c.Ref), c.Verification.HostnameError)
		}
	}
	return nil
}

func defaultGets(t Target) string {
	for _, p := range t.Probes {
		if p.ID != "default" {
			continue
		}
		if n := p.Negotiated; n != nil {
			if n.Group != nil {
				return n.Version + " " + n.Group.Name
			}
			return n.Version
		}
		return p.Result
	}
	return "-"
}

func certKeys(t Target) string {
	var keys []string
	seen := map[string]bool{}
	for _, c := range t.Certificates {
		if k := c.PublicKey.keyLabel(); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return strings.Join(keys, ", ")
}

func trusted(t Target) string {
	if len(t.Certificates) == 0 {
		return "-"
	}
	n := 0
	for _, c := range t.Certificates {
		if c.Verification.ChainTrusted {
			n++
		}
	}
	return fmt.Sprintf("%d/%d", n, len(t.Certificates))
}

func shortRef(ref string) string {
	ref = strings.TrimPrefix(ref, "sha256:")
	if len(ref) > 8 {
		return ref[:8]
	}
	return ref
}

func legacyMark(v string) string {
	if v == "unknown" {
		return "?"
	}
	return v
}

// printNotes prints each probe note once, with the probes that carry it.
func printNotes(w io.Writer, r Report) {
	var order []string
	ids := map[string][]string{}
	for _, t := range r.Targets {
		for _, p := range t.Probes {
			if p.note == "" {
				continue
			}
			if _, ok := ids[p.note]; !ok {
				order = append(order, p.note)
			}
			if !contains(ids[p.note], p.ID) {
				ids[p.note] = append(ids[p.note], p.ID)
			}
		}
	}
	for _, n := range order {
		fmt.Fprintf(w, "Note (%s): %s\n", strings.Join(ids[n], ", "), n)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
