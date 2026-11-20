// Package openvex reads and writes OpenVEX documents (https://openvex.dev).
//
// Reading accepts v0.2.0 and the older v0.0.x form, where the vulnerability and the products are
// plain strings. Writing produces v0.2.0.
package openvex

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/corefense-security/trowl/internal/py"
)

const Context = "https://openvex.dev/ns/v0.2.0"

// The statuses and justifications the spec allows.
var (
	statuses       = map[string]bool{"not_affected": true, "affected": true, "fixed": true, "under_investigation": true}
	justifications = map[string]bool{"component_not_present": true, "vulnerable_code_not_present": true,
		"vulnerable_code_not_in_execute_path": true, "vulnerable_code_cannot_be_controlled_by_adversary": true,
		"inline_mitigations_already_exist": true}
)

type Doc struct {
	Context    string       `json:"@context"`
	ID         string       `json:"@id"`
	Author     string       `json:"author"`
	Timestamp  string       `json:"timestamp"`
	Version    int          `json:"version"`
	Tooling    string       `json:"tooling,omitempty"`
	Statements []*Statement `json:"statements"`
}

type Statement struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Timestamp     string        `json:"timestamp,omitempty"`
	Products      []Product     `json:"products"`
	Status        string        `json:"status"`
	Justification string        `json:"justification,omitempty"`
	Impact        string        `json:"impact_statement,omitempty"`
	Action        string        `json:"action_statement,omitempty"`
	Notes         string        `json:"status_notes,omitempty"`

	// When the statement was made, from its own timestamp or else the document's. Not written.
	Time time.Time `json:"-"`
}

type Vulnerability struct {
	ID      string   `json:"@id,omitempty"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type Product struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Subcomponents []Product         `json:"subcomponents,omitempty"`
}

// Is reports whether raw is an OpenVEX document, by its @context.
func Is(raw []byte) bool {
	var d struct {
		Context json.RawMessage `json:"@context"`
	}
	if json.Unmarshal(raw, &d) != nil || d.Context == nil {
		return false
	}
	var one string
	var many []string
	if json.Unmarshal(d.Context, &one) == nil {
		many = []string{one}
	} else if json.Unmarshal(d.Context, &many) != nil {
		return false
	}
	for _, c := range many {
		if strings.HasPrefix(c, "https://openvex.dev/ns") {
			return true
		}
	}
	return false
}

// The document as read. Strings and objects are both accepted where v0.0.x used strings.
type rawDoc struct {
	Timestamp  string `json:"timestamp"`
	Statements []struct {
		Vulnerability json.RawMessage   `json:"vulnerability"`
		Timestamp     string            `json:"timestamp"`
		LastUpdated   string            `json:"last_updated"`
		Products      []json.RawMessage `json:"products"`
		Subcomponents []json.RawMessage `json:"subcomponents"`
		Status        string            `json:"status"`
		Justification string            `json:"justification"`
		Impact        string            `json:"impact_statement"`
		Action        string            `json:"action_statement"`
		Notes         string            `json:"status_notes"`
	} `json:"statements"`
}

// Read loads an OpenVEX file. A statement without a vulnerability, a product or a valid status
// is an error, so a broken file doesn't quietly change nothing.
func Read(path string) (*Doc, error) {
	where := py.CleanPath(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !Is(raw) {
		return nil, fmt.Errorf("%s: not an OpenVEX document (no openvex.dev @context)", where)
	}
	var rd rawDoc
	if err := json.Unmarshal(raw, &rd); err != nil {
		return nil, fmt.Errorf("%s: not valid OpenVEX JSON: %w", where, err)
	}
	if len(rd.Statements) == 0 {
		return nil, fmt.Errorf("%s: has no statements", where)
	}
	docTime := parseTime(rd.Timestamp)
	doc := &Doc{Timestamp: rd.Timestamp}
	for i, s := range rd.Statements {
		bad := func(what string) error { return fmt.Errorf("%s: statement %d %s", where, i+1, what) }
		st := &Statement{Status: s.Status, Justification: s.Justification, Impact: s.Impact, Action: s.Action,
			Notes: s.Notes, Timestamp: s.Timestamp}
		if !statuses[s.Status] {
			return nil, bad(fmt.Sprintf("has status %q, not one of not_affected, affected, fixed or under_investigation", s.Status))
		}
		if s.Justification != "" && !justifications[s.Justification] {
			return nil, bad(fmt.Sprintf("has an unknown justification %q", s.Justification))
		}
		if err := st.Vulnerability.read(s.Vulnerability); err != nil {
			return nil, bad(err.Error())
		}
		var subs []Product
		for _, r := range s.Subcomponents {
			p, err := readProduct(r)
			if err != nil {
				return nil, bad(err.Error())
			}
			subs = append(subs, p)
		}
		for _, r := range s.Products {
			p, err := readProduct(r)
			if err != nil {
				return nil, bad(err.Error())
			}
			// v0.0.x lists subcomponents beside the products, for all of them.
			if len(p.Subcomponents) == 0 {
				p.Subcomponents = subs
			}
			st.Products = append(st.Products, p)
		}
		if len(st.Products) == 0 {
			return nil, bad("names no products")
		}
		st.Time = docTime
		for _, t := range []string{s.Timestamp, s.LastUpdated} {
			if tt := parseTime(t); tt.After(st.Time) {
				st.Time = tt
			}
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func (v *Vulnerability) read(raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("names no vulnerability")
	}
	var name string
	if json.Unmarshal(raw, &name) == nil {
		v.Name = name
	} else if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("has a bad vulnerability: %w", err)
	}
	if v.Name == "" && v.ID == "" {
		return fmt.Errorf("names no vulnerability")
	}
	return nil
}

func readProduct(raw json.RawMessage) (Product, error) {
	var id string
	if json.Unmarshal(raw, &id) == nil {
		return Product{ID: id}, nil
	}
	var p Product
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("has a bad product: %w", err)
	}
	if p.ID == "" && len(p.Identifiers) == 0 {
		return p, fmt.Errorf("has a product with no @id or identifiers")
	}
	return p, nil
}

// CVEs lists the CVE IDs a statement is about, from its name, @id and aliases.
func (s *Statement) CVEs() []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range append([]string{s.Vulnerability.Name, s.Vulnerability.ID}, s.Vulnerability.Aliases...) {
		id = strings.ToUpper(strings.TrimSpace(id))
		// An @id may be a URL ending in the CVE ID.
		if i := strings.LastIndex(id, "/"); i >= 0 {
			id = id[i+1:]
		}
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Keys lists a product's @id and every value under its identifiers.
func (p Product) Keys() []string {
	var out []string
	if p.ID != "" {
		out = append(out, p.ID)
	}
	names := make([]string, 0, len(p.Identifiers))
	for k := range p.Identifiers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if v := p.Identifiers[k]; v != "" && v != p.ID {
			out = append(out, v)
		}
	}
	return out
}

// New makes a document for the statements Trowl writes.
func New(statements []*Statement, timestamp time.Time, version string) *Doc {
	sort.SliceStable(statements, func(i, j int) bool {
		a, b := statements[i], statements[j]
		if a.Vulnerability.Name != b.Vulnerability.Name {
			return a.Vulnerability.Name < b.Vulnerability.Name
		}
		return a.Products[0].ID < b.Products[0].ID
	})
	if statements == nil {
		statements = []*Statement{}
	}
	return &Doc{Context: Context, ID: "urn:uuid:" + uuid4(), Author: "Trowl",
		Timestamp: timestamp.UTC().Format(time.RFC3339), Version: 1, Tooling: "trowl/" + version, Statements: statements}
}

// Write saves the document as indented JSON.
func (d *Doc) Write(path string) error {
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func uuid4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
