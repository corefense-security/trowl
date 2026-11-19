package sbom

// CycloneDX JSON from any tool.
//
// Every component is a CVE target. Scope "excluded" means build-time only.
// Presence is checked only when a component nests "file" components.
// VEX comes from vulnerabilities and from pedigree patches that resolve a CVE.
// Producer-specific rules go in a cdxProfile.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/corefense-security/trowl/internal/py"
)

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxComponent struct {
	BomRef     string    `json:"bom-ref"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Cpe        string    `json:"cpe"`
	Purl       string    `json:"purl"`
	Scope      string    `json:"scope"`
	Hashes     []cdxHash `json:"hashes"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Components []cdxComponent `json:"components"`
	Pedigree   *struct {
		Patches []struct {
			Resolves []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"resolves"`
		} `json:"patches"`
	} `json:"pedigree"`
}

type cdxVuln struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	Published   string `json:"published"`
	Ratings     []struct {
		Score    json.RawMessage `json:"score"`
		Severity string          `json:"severity"`
		Method   string          `json:"method"`
		Vector   string          `json:"vector"`
	} `json:"ratings"`
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Analysis *struct {
		State         string `json:"state"`
		Justification string `json:"justification"`
		Detail        string `json:"detail"`
	} `json:"analysis"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

type cdxBom struct {
	BomFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Component *cdxComponent   `json:"component"`
		Tools     json.RawMessage `json:"tools"`
	} `json:"metadata"`
	Components   []cdxComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
	Vulnerabilities []cdxVuln `json:"vulnerabilities"`
}

// cdxProfile holds one producer's rules. match gets the tool names from metadata.tools.
// apply runs after the generic load.
type cdxProfile struct {
	name  string
	match func(tools []string) bool
	apply func(bom *cdxBom, sb *Sbom)
}

// cdxProfiles are tried in order. The first match applies.
var cdxProfiles []cdxProfile

// cdxTools returns the tool names in metadata.tools. It reads the 1.4 list and the 1.5 object.
func cdxTools(raw json.RawMessage) []string {
	type tool struct {
		Name string `json:"name"`
	}
	var list []tool
	if json.Unmarshal(raw, &list) != nil {
		var obj struct {
			Components []tool `json:"components"`
			Services   []tool `json:"services"`
		}
		json.Unmarshal(raw, &obj)
		list = append(obj.Components, obj.Services...)
	}
	var names []string
	for _, t := range list {
		if t.Name != "" {
			names = append(names, t.Name)
		}
	}
	return names
}

// cdxStates maps analysis states to VEX statuses.
var cdxStates = map[string]string{
	"resolved":               "fixed",
	"resolved_with_pedigree": "fixed",
	"not_affected":           "not_affected",
	"false_positive":         "not_affected",
	"exploitable":            "affected",
	"in_triage":              "under_investigation",
}

// cdxMethods maps rating methods to CVSS versions.
var cdxMethods = map[string]string{"CVSSv2": "2", "CVSSv3": "3", "CVSSv31": "3", "CVSSv4": "4"}

// isCycloneDX reports whether raw is CycloneDX JSON.
func isCycloneDX(raw []byte) bool {
	var top struct {
		BomFormat string `json:"bomFormat"`
	}
	return json.Unmarshal(raw, &top) == nil && top.BomFormat == "CycloneDX"
}

// cycloneDXXML reports whether raw looks like CycloneDX XML.
func cycloneDXXML(raw []byte) bool {
	head := raw
	if len(head) > 1024 {
		head = head[:1024]
	}
	s := strings.TrimSpace(string(head))
	return strings.HasPrefix(s, "<") && strings.Contains(s, "cyclonedx.org/schema/bom")
}

type bomLink struct {
	serial  string
	version int
	ref     string
}

// parseBOMLink reads urn:cdx:SERIAL/VERSION#REF. ok is false for anything else.
func parseBOMLink(s string) (bomLink, bool) {
	rest, ok := strings.CutPrefix(s, "urn:cdx:")
	if !ok {
		return bomLink{}, false
	}
	head, frag, ok := strings.Cut(rest, "#")
	if !ok || frag == "" {
		return bomLink{}, false
	}
	serial, ver, ok := strings.Cut(head, "/")
	n, err := strconv.Atoi(ver)
	if !ok || serial == "" || err != nil || n < 1 {
		return bomLink{}, false
	}
	ref, err := url.PathUnescape(frag)
	if err != nil {
		return bomLink{}, false
	}
	return bomLink{serial: serial, version: n, ref: ref}, true
}

// cdxCVE returns the vulnerability's CVE id. A GHSA id falls back to the first CVE reference.
func cdxCVE(v *cdxVuln) string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, r := range v.References {
		if strings.HasPrefix(r.ID, "CVE-") {
			return r.ID
		}
	}
	return v.ID
}

// loadCycloneDX builds the Sbom from CycloneDX JSON.
func loadCycloneDX(raw []byte) (*Sbom, error) {
	var bom cdxBom
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("not valid CycloneDX JSON: %w", err)
	}
	sb := &Sbom{Packages: map[string]*Package{}, Generates: newIDList(), RuntimeDeps: newIDList(),
		BuildDeps: newIDList(), Vulns: newIDList(), vex: map[pair]string{}, vexNotes: map[pair]string{}, stated: map[pair]string{}, matched: map[pair]bool{}, nameOnly: map[pair]bool{}, fixes: map[pair]Fix{},
		assessed: map[pair]*Assessment{}, VulnInfo: map[string]*VulnInfo{}, Format: "CycloneDX " + bom.SpecVersion}
	if bom.SpecVersion == "" {
		sb.Format = "CycloneDX"
	}
	root := ""
	if mc := bom.Metadata.Component; mc != nil {
		sb.Name, root = mc.Name, mc.BomRef
	}

	var add func(c *cdxComponent)
	add = func(c *cdxComponent) {
		if c.Type == "file" {
			return // files belong to their parent
		}
		id := c.BomRef
		if id == "" {
			id = c.Name + "@" + c.Version
		}
		if _, dup := sb.Packages[id]; dup || id == root {
			for n := 2; ; n++ {
				if _, taken := sb.Packages[fmt.Sprintf("%s#%d", id, n)]; !taken {
					id = fmt.Sprintf("%s#%d", id, n)
					break
				}
			}
		}
		name := c.Name
		if name == "" {
			name = id
		}
		pkg := &Package{ID: id, Name: name, Version: c.Version, Role: "package", Purl: c.Purl, Cpes: []string{},
			BuildOnly: c.Scope == "excluded"}
		if c.Cpe != "" {
			pkg.Cpes = append(pkg.Cpes, c.Cpe)
		}
		for i := range c.Components {
			f := &c.Components[i]
			if f.Type != "file" || f.Name == "" {
				continue
			}
			var sha *string
			for _, h := range f.Hashes {
				if h.Alg == "SHA-256" && h.Content != "" {
					v := strings.ToLower(h.Content)
					sha = &v
				}
			}
			pkg.Files = append(pkg.Files, File{Name: f.Name, Sha256: sha})
		}
		sb.Packages[id] = pkg
		sb.PackageOrder = append(sb.PackageOrder, id)
		if c.Pedigree != nil {
			for _, p := range c.Pedigree.Patches {
				for _, r := range p.Resolves {
					cve := r.ID
					if !strings.HasPrefix(cve, "CVE-") {
						cve = r.Name
					}
					if strings.HasPrefix(cve, "CVE-") {
						sb.listCVE(id, cve)
						sb.vulnInfo(cve)
						sb.vex[pair{cve, id}] = "fixed"
					}
				}
			}
		}
		for i := range c.Components {
			add(&c.Components[i])
		}
	}
	for i := range bom.Components {
		add(&bom.Components[i])
	}
	// Some tools nest the product's parts under the root component instead.
	if mc := bom.Metadata.Component; mc != nil {
		for i := range mc.Components {
			add(&mc.Components[i])
		}
	}

	// CycloneDX doesn't say if a dependency is for build or runtime. One on a build-only
	// component is a build edge.
	for _, d := range bom.Dependencies {
		if _, ok := sb.Packages[d.Ref]; !ok {
			continue
		}
		for _, dep := range filter(d.DependsOn, sb.Packages) {
			if sb.Packages[dep].BuildOnly {
				sb.BuildDeps.add(d.Ref, dep)
			} else {
				sb.RuntimeDeps.add(d.Ref, dep)
			}
		}
	}

	sb.Serial, sb.BomVersion = strings.TrimPrefix(bom.SerialNumber, "urn:uuid:"), bom.Version
	if sb.BomVersion == 0 {
		sb.BomVersion = 1
	}
	// A BOM-Link counts only when it names this BOM. Without a serial that can't be checked.
	// Refs to unlisted components are skipped too, such as Buildroot's virtual packages.
	embedded := func(ref string) (string, bool) {
		comp := ref
		if link, ok := parseBOMLink(ref); ok {
			if sb.Serial == "" || link.serial != sb.Serial || link.version != sb.BomVersion {
				return "", false
			}
			comp = link.ref
		}
		return comp, sb.Packages[comp] != nil
	}
	res, err := sb.applyVulns(bom.Vulnerabilities, embedded, false)
	if err != nil {
		return nil, err
	}
	sb.VEXSkipped = res.Skipped

	tools := cdxTools(bom.Metadata.Tools)
	if len(tools) > 0 {
		sb.Producer = tools[0]
	}
	for _, p := range cdxProfiles {
		if p.match(tools) {
			p.apply(&bom, sb)
			break
		}
	}
	return sb, nil
}

// vulnInfo returns the CVE's details and adds an empty entry when there is none.
func (sb *Sbom) vulnInfo(cve string) *VulnInfo {
	vi := sb.VulnInfo[cve]
	if vi == nil {
		vi = &VulnInfo{CVSS: map[string]*CVSS{}}
		sb.VulnInfo[cve] = vi
	}
	return vi
}

// VEXResult counts what a VEX file did to the SBOM.
type VEXResult struct {
	Statements int // vulnerabilities in the file
	Applied    int // statement and component pairs that reached a component
	Skipped    int // affects entries that point at another BOM or at no component
}

// resolver turns an affects ref into a component id. ok is false when the ref is skipped.
type resolver func(ref string) (comp string, ok bool)

// applyVulns records the statuses and CVE details of vulns. A VEX file needs an analysis on
// every statement. An SBOM may leave it out when nothing was analysed.
func (sb *Sbom) applyVulns(vulns []cdxVuln, resolve resolver, needAnalysis bool) (VEXResult, error) {
	res := VEXResult{Statements: len(vulns)}
	for i := range vulns {
		v := &vulns[i]
		if v.ID == "" {
			return res, fmt.Errorf("vulnerability %d has no id", i+1)
		}
		name := fmt.Sprintf("vulnerability %d (%s)", i+1, v.ID)
		if len(v.Affects) == 0 {
			return res, fmt.Errorf("%s has no affects", name)
		}
		a := v.Analysis
		switch {
		case a == nil && needAnalysis:
			return res, fmt.Errorf("%s has no analysis", name)
		case a != nil && a.State == "":
			return res, fmt.Errorf("%s has an analysis with no state", name)
		case a != nil && cdxStates[a.State] == "":
			return res, fmt.Errorf("%s has an unknown analysis state %q", name, a.State)
		}
		var comps []string
		for _, af := range v.Affects {
			if af.Ref == "" {
				return res, fmt.Errorf("%s has an affects entry with no ref", name)
			}
			comp, ok := resolve(af.Ref)
			if !ok {
				res.Skipped++
				continue
			}
			comps = append(comps, comp)
		}
		cve := cdxCVE(v)
		for _, comp := range comps {
			sb.listCVE(comp, cve)
		}
		if len(comps) == 0 {
			continue
		}
		res.Applied += len(comps)
		vi := sb.vulnInfo(cve)
		if vi.Description == "" {
			if vi.Description = v.Description; vi.Description == "" {
				vi.Description = v.Detail
			}
		}
		if vi.Published == "" {
			vi.Published = v.Published
		}
		for _, r := range v.Ratings {
			ver, ok := cdxMethods[r.Method]
			if !ok {
				continue
			}
			score, ok := parseScore(r.Score)
			if !ok {
				continue
			}
			if cur, have := vi.CVSS[ver]; !have || score > cur.Score {
				if !have {
					vi.CVSSOrder = append(vi.CVSSOrder, ver)
				}
				vi.CVSS[ver] = &CVSS{Score: score, Vector: r.Vector, Severity: r.Severity}
			}
		}
		if a == nil {
			continue
		}
		notes := a.Detail
		if a.Justification != "" {
			notes = strings.TrimSpace(a.Justification + ". " + notes)
		}
		for _, comp := range comps {
			k := pair{cve, comp}
			sb.vex[k] = cdxStates[a.State]
			if notes != "" {
				sb.vexNotes[k] = notes
			}
			// A --vex file that restates the CVE replaces the justification too.
			if sb.vex[k] == "not_affected" && a.Justification == "code_not_present" {
				if sb.codeAbsent == nil {
					sb.codeAbsent = map[pair]bool{}
				}
				sb.codeAbsent[k] = true
			} else {
				delete(sb.codeAbsent, k)
			}
			if fix := statedFixRe.FindStringSubmatch(a.Detail); fix != nil {
				sb.stated[k] = fix[1]
			}
		}
	}
	return res, nil
}

// LoadVEX applies a separate CycloneDX VEX file to a CycloneDX SBOM like meta-cyclonedx writes.
// Each affects entry must be a BOM-Link to the SBOM's serial number and version like Trivy
// requires. Entries for another BOM or an unknown component are skipped. A file where every
// entry is skipped belongs to another SBOM and is refused.
func LoadVEX(sb *Sbom, path string) (VEXResult, error) {
	where := py.CleanPath(path)
	if !strings.HasPrefix(sb.Format, "CycloneDX") {
		return VEXResult{}, fmt.Errorf("%s: --vex needs a CycloneDX SBOM but the SBOM is %s", where, sb.Format)
	}
	if sb.Serial == "" {
		return VEXResult{}, fmt.Errorf("%s: the SBOM has no serialNumber so the VEX can't be matched to it", where)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return VEXResult{}, err
	}
	if cycloneDXXML(raw) {
		return VEXResult{}, fmt.Errorf("%s: CycloneDX XML isn't read. Pass the JSON form", where)
	}
	if !isCycloneDX(raw) {
		return VEXResult{}, fmt.Errorf("%s: not a CycloneDX JSON VEX document", where)
	}
	var vex struct {
		Vulnerabilities *[]cdxVuln `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &vex); err != nil {
		return VEXResult{}, fmt.Errorf("%s: not valid CycloneDX JSON: %w", where, err)
	}
	if vex.Vulnerabilities == nil {
		return VEXResult{}, fmt.Errorf("%s: has no vulnerabilities", where)
	}
	split := func(ref string) (string, bool) {
		link, ok := parseBOMLink(ref)
		if !ok || link.serial != sb.Serial || link.version != sb.BomVersion || sb.Packages[link.ref] == nil {
			return "", false
		}
		return link.ref, true
	}
	res, err := sb.applyVulns(*vex.Vulnerabilities, split, true)
	if err != nil {
		return res, fmt.Errorf("%s: %w", where, err)
	}
	if res.Statements > 0 && res.Applied == 0 {
		return res, fmt.Errorf("%s: none of its %d statements point at this SBOM (urn:cdx:%s/%d)",
			where, res.Statements, sb.Serial, sb.BomVersion)
	}
	return res, nil
}
