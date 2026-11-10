// Package sbom reads SPDX 3.0 JSON-LD (packages, files, relationships and vulnerabilities),
// compares it with the image, and builds the CVE rows.
//
// Written against Yocto's create-spdx-3.0 output, but only relies on core/software/security
// profile terms, so other SPDX 3.0 producers load too. Element roles are taken from Yocto's
// spdxId layout (".../recipe/x", ".../package/x") when present, otherwise from
// software_primaryPurpose.
package sbom

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/corefense-security/trowl/internal/py"
)

var binaryPurposes = map[string]bool{"install": true, "application": true, "library": true, "firmware": true,
	"operatingSystem": true, "executable": true, "container": true}

var vexTypes = map[string]string{
	"security_VexFixedVulnAssessmentRelationship":              "fixed",
	"security_VexNotAffectedVulnAssessmentRelationship":        "not_affected",
	"security_VexAffectedVulnAssessmentRelationship":           "affected",
	"security_VexUnderInvestigationVulnAssessmentRelationship": "under_investigation",
}

var cvssTypes = map[string]string{
	"security_CvssV2VulnAssessmentRelationship": "2",
	"security_CvssV3VulnAssessmentRelationship": "3",
	"security_CvssV4VulnAssessmentRelationship": "4",
}

type File struct {
	Name   string
	Sha256 *string
}

type Package struct {
	ID, Name, Version, Role, Purl string
	Cpes                          []string
	Files                         []File
}

type CVSS struct {
	Score            float64
	Vector, Severity string
}

type VulnInfo struct {
	Description, Published string
	CVSS                   map[string]*CVSS
	CVSSOrder              []string // versions in first-seen order
}

// Ordered maps keep Python's dict insertion order where the report depends on it.
type IDList struct {
	Keys []string
	M    map[string][]string
}

func newIDList() *IDList { return &IDList{M: map[string][]string{}} }

func (l *IDList) add(k string, vs ...string) {
	if _, ok := l.M[k]; !ok {
		l.Keys = append(l.Keys, k)
		l.M[k] = []string{}
	}
	l.M[k] = append(l.M[k], vs...)
}

type pair struct{ a, b string }

type Sbom struct {
	Packages     map[string]*Package
	PackageOrder []string
	Generates    *IDList // recipe id -> binary package ids
	RuntimeDeps  *IDList // package id -> package ids
	BuildDeps    *IDList // recipe id -> recipe ids
	Vulns        *IDList // component id -> CVE ids (sorted, unique)
	vex          map[pair]string
	vexNotes     map[pair]string
	stated       map[pair]string // fix version named in the VEX text (sbom-cve-check)
	matched      map[pair]bool   // statuses that came from a version match
	nameOnly     map[pair]bool   // version matches with no vendor to back them up
	fixes        map[pair]Fix    // upstream fix, from the CVE record
	assessed     map[pair]*Assessment
	Name         string
	VulnInfo     map[string]*VulnInfo
	Inventory    string // the package database this came from, when it isn't a real SBOM
}

// Vex returns the SBOM's VEX status for (CVE, component), or "".
func (s *Sbom) Vex(cve, comp string) string { return s.vex[pair{cve, comp}] }

// statedFixRe finds the version in sbom-cve-check's VEX text: "May need backporting (fixed from
// 6.18.53)", "Needs backporting (originally fixed in 7.2)", "fixed-version: Originally fixed in
// 6.12", "cpe-stable-backport: Backported in 6.18.40". "fixed from >1.38" names no exact version.
var statedFixRe = regexp.MustCompile(`(?i)(?:fixed from|fixed in|backported in) ([0-9][^\s)]*)`)

// StatedFix is the fix version the SBOM names for a CVE, "" if none.
func (s *Sbom) StatedFix(cve, comp string) string { return s.stated[pair{cve, comp}] }

func (s *Sbom) VexNotes(cve, comp string) string { return s.vexNotes[pair{cve, comp}] }

type ident struct {
	Type       string `json:"externalIdentifierType"`
	Identifier any    `json:"identifier"`
}

type hash struct {
	Algorithm string  `json:"algorithm"`
	Value     *string `json:"hashValue"`
}

// element decodes only the fields trowl reads.
type element struct {
	SpdxID       *string         `json:"spdxId"`
	AtID         *string         `json:"@id"`
	Type         *string         `json:"type"`
	Name         *string         `json:"name"`
	Version      *string         `json:"software_packageVersion"`
	Purl         *string         `json:"software_packageUrl"`
	Purpose      *string         `json:"software_primaryPurpose"`
	ExtIDs       []ident         `json:"externalIdentifier"`
	Verified     []hash          `json:"verifiedUsing"`
	Description  *string         `json:"description"`
	Summary      *string         `json:"summary"`
	Published    *string         `json:"security_publishedTime"`
	RelType      *string         `json:"relationshipType"`
	From         *string         `json:"from"`
	To           json.RawMessage `json:"to"`
	StatusNotes  *string         `json:"security_statusNotes"`
	Action       *string         `json:"security_actionStatement"`
	Score        json.RawMessage `json:"security_score"`
	VectorString *string         `json:"security_vectorString"`
	CVSSSeverity *string         `json:"security_severity"`
	Scope        *string         `json:"scope"`
}

func s(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (e *element) key() string {
	if e.SpdxID != nil && *e.SpdxID != "" {
		return *e.SpdxID
	}
	if e.AtID != nil {
		return *e.AtID
	}
	return "\x00none"
}

func role(e *element) string {
	sid := s(e.SpdxID)
	for _, marker := range []string{"recipe", "package", "source", "rootfs"} {
		if strings.Contains(sid, "/"+marker+"/") {
			return marker
		}
	}
	if e.Purpose != nil && binaryPurposes[*e.Purpose] {
		return "package"
	}
	if s(e.Purpose) == "source" {
		return "source"
	}
	return "other"
}

func sha256Of(e *element) *string {
	for _, h := range e.Verified {
		if h.Algorithm == "sha256" {
			return h.Value
		}
	}
	return nil
}

func toList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	json.Unmarshal(raw, &many)
	return many
}

func parseScore(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		f, err := strconv.ParseFloat(strings.TrimSpace(str), 64)
		return f, err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	}
	var f float64
	return f, json.Unmarshal(raw, &f) == nil
}

func idString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// spdx3Elements returns the elements of an SPDX 3.0 JSON-LD document: its @graph, or the
// document itself when it is a bare list of elements. Any other format is refused by name, so
// that an SBOM trowl can't read stops the scan rather than giving a report without its data.
//
// Yocto writes SPDX 3.0 since 5.0 (scarthgap). SPDX 2.x, which older Yocto releases and
// Android write, describes packages in a different model (packages[], relationships[]), and
// reading it as 3.0 would find no packages at all.
func spdx3Elements(raw []byte) ([]json.RawMessage, error) {
	const want = "trowl reads SPDX 3.0 JSON-LD SBOMs, such as Yocto 5.0 (scarthgap) and later write"
	var top struct {
		Context     json.RawMessage   `json:"@context"`
		Graph       []json.RawMessage `json:"@graph"`
		SpdxVersion string            `json:"spdxVersion"`
		BomFormat   string            `json:"bomFormat"`
	}
	if err := json.Unmarshal(raw, &top); err == nil {
		switch {
		case top.SpdxVersion != "":
			return nil, fmt.Errorf("%s isn't supported: %s", top.SpdxVersion, want)
		case top.BomFormat != "":
			return nil, fmt.Errorf("%s isn't supported: %s", top.BomFormat, want)
		case top.Graph == nil:
			return nil, fmt.Errorf("not an SPDX 3.0 JSON-LD document (no @graph): %s", want)
		case len(top.Context) > 0 && !strings.Contains(string(top.Context), "spdx.org/rdf/3."):
			return nil, fmt.Errorf("its @context isn't SPDX 3: %s", want)
		}
		return top.Graph, nil
	}
	// A bare list of elements: each SPDX 3 element has a type.
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("not JSON, so not an SPDX 3.0 JSON-LD document (tag-value and RDF/XML aren't read): %s", want)
	}
	for _, it := range items {
		var e struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(it, &e) != nil || e.Type == "" {
			return nil, fmt.Errorf("a list of elements without SPDX 3 types: %s", want)
		}
	}
	return items, nil
}

func Load(path string) (*Sbom, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	items, err := spdx3Elements(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", py.CleanPath(path), err)
	}
	raw = nil
	graph := make([]*element, 0, len(items))
	for _, it := range items {
		var e element
		if json.Unmarshal(it, &e) == nil {
			graph = append(graph, &e)
		}
	}
	items = nil

	var order []string
	byID := map[string]*element{}
	for _, e := range graph {
		k := e.key()
		if _, ok := byID[k]; !ok {
			order = append(order, k)
		}
		byID[k] = e
	}

	sb := &Sbom{Packages: map[string]*Package{}, Generates: newIDList(), RuntimeDeps: newIDList(),
		BuildDeps: newIDList(), Vulns: newIDList(), vex: map[pair]string{}, vexNotes: map[pair]string{}, stated: map[pair]string{}, matched: map[pair]bool{}, nameOnly: map[pair]bool{}, fixes: map[pair]Fix{},
		assessed: map[pair]*Assessment{}, VulnInfo: map[string]*VulnInfo{}}
	for _, sid := range order {
		e := byID[sid]
		if s(e.Type) != "software_Package" {
			continue
		}
		cpes := []string{}
		for _, x := range e.ExtIDs {
			if strings.HasPrefix(x.Type, "cpe") {
				cpes = append(cpes, idString(x.Identifier))
			}
		}
		name := sid
		if e.Name != nil {
			name = *e.Name
		}
		sb.Packages[sid] = &Package{ID: sid, Name: name, Version: s(e.Version), Role: role(e), Purl: s(e.Purl), Cpes: cpes}
		sb.PackageOrder = append(sb.PackageOrder, sid)
	}

	cveOf := map[string]string{}
	info := func(cve string) *VulnInfo {
		vi, ok := sb.VulnInfo[cve]
		if !ok {
			vi = &VulnInfo{CVSS: map[string]*CVSS{}}
			sb.VulnInfo[cve] = vi
		}
		return vi
	}
	for _, sid := range order {
		e := byID[sid]
		if s(e.Type) != "security_Vulnerability" {
			continue
		}
		var cve string
		for _, x := range e.ExtIDs {
			if x.Type == "cve" {
				cve = idString(x.Identifier)
				break
			}
		}
		if cve == "" {
			if e.Name != nil {
				cve = *e.Name
			} else {
				cve = sid[strings.LastIndex(sid, "/")+1:]
			}
		}
		cveOf[sid] = cve
		vi := info(cve)
		// Yocto writes one element per recipe plus one from sbom-cve-check; keep the first text.
		if vi.Description == "" {
			if d := s(e.Description); d != "" {
				vi.Description = d
			} else {
				vi.Description = s(e.Summary)
			}
		}
		if vi.Published == "" {
			vi.Published = s(e.Published)
		}
	}
	mapCVE := func(id string) string {
		if c, ok := cveOf[id]; ok {
			return c
		}
		return id
	}

	// VEX pairs are collected per raw (vulnerability, component) first and mapped to CVE ids
	// afterwards, so a CVE described twice resolves the way the Python dict did.
	type vexVal struct{ status, notes, fix string }
	var vexOrder []pair
	vexRaw := map[pair]*vexVal{}
	vulnRaw := newIDList()
	for _, e := range graph {
		if e.RelType == nil {
			continue
		}
		t, rel, src, dsts := s(e.Type), *e.RelType, s(e.From), toList(e.To)
		if v, ok := vexTypes[t]; ok {
			for _, d := range dsts {
				k := pair{src, d}
				cur, ok := vexRaw[k]
				if !ok {
					cur = &vexVal{}
					vexRaw[k] = cur
					vexOrder = append(vexOrder, k)
				}
				cur.status = v
				if v := statedFixRe.FindStringSubmatch(s(e.Action) + " " + s(e.StatusNotes)); v != nil {
					cur.fix = v[1]
				}
				if s(e.StatusNotes) != "" {
					cur.notes = *e.StatusNotes
				}
			}
			continue
		}
		if ver, ok := cvssTypes[t]; ok {
			vi := info(mapCVE(src))
			score, ok := parseScore(e.Score)
			if !ok {
				continue
			}
			cur, have := vi.CVSS[ver]
			best := -1.0
			if have {
				best = cur.Score
			}
			if score > best {
				if !have {
					vi.CVSSOrder = append(vi.CVSSOrder, ver)
				}
				vi.CVSS[ver] = &CVSS{Score: score, Vector: s(e.VectorString), Severity: s(e.CVSSSeverity)}
			}
			continue
		}
		pkg, isPkg := sb.Packages[src]
		if !isPkg && rel != "hasAssociatedVulnerability" {
			continue
		}
		switch rel {
		case "contains":
			for _, d := range dsts {
				if fe, ok := byID[d]; ok && s(fe.Type) == "software_File" {
					pkg.Files = append(pkg.Files, File{s(fe.Name), sha256Of(fe)})
				}
			}
		case "generates":
			sb.Generates.add(src, filter(dsts, sb.Packages)...)
		case "dependsOn":
			isRuntime := s(e.Scope) == "runtime" || (e.Scope == nil && pkg.Role == "package")
			if isRuntime {
				sb.RuntimeDeps.add(src, filter(dsts, sb.Packages)...)
			} else {
				sb.BuildDeps.add(src, filter(dsts, sb.Packages)...)
			}
		case "hasAssociatedVulnerability":
			var keep []string
			for _, d := range dsts {
				if _, ok := byID[d]; ok {
					keep = append(keep, d)
				}
			}
			vulnRaw.add(src, keep...)
		}
	}

	// Build components: Yocto marks them with ".../recipe/..." ids, but any producer that links a
	// component to the binary packages it builds (SPDX "generates") describes the same thing.
	for _, src := range sb.Generates.Keys {
		if sb.Packages[src].Role == "other" {
			sb.Packages[src].Role = "recipe"
		}
	}

	for _, k := range vexOrder {
		v := vexRaw[k]
		sb.vex[pair{mapCVE(k.a), k.b}] = v.status
		if v.notes != "" {
			sb.vexNotes[pair{mapCVE(k.a), k.b}] = v.notes
		}
		if v.fix != "" {
			sb.stated[pair{mapCVE(k.a), k.b}] = v.fix
		}
	}

	for _, comp := range vulnRaw.Keys {
		set := map[string]bool{}
		for _, v := range vulnRaw.M[comp] {
			set[mapCVE(v)] = true
		}
		ids := make([]string, 0, len(set))
		for k := range set {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		sb.Vulns.add(comp, ids...)
	}

	for _, e := range graph {
		if s(e.Type) == "software_Sbom" {
			if n := s(e.Name); n != "" {
				sb.Name = n
			} else {
				sid := s(e.SpdxID)
				sb.Name = sid[strings.LastIndex(sid, "/")+1:]
			}
			break
		}
	}
	return sb, nil
}

func filter(ids []string, pkgs map[string]*Package) []string {
	var out []string
	for _, d := range ids {
		if _, ok := pkgs[d]; ok {
			out = append(out, d)
		}
	}
	return out
}
