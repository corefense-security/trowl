package sbom

import (
	"sort"
	"strings"

	"github.com/corefense-security/trowl/internal/pyjson"
)

// CPE is one component's CPE identity, for version matching.
type CPE struct {
	Comp, Vendor, Product, Version string
}

// FromInventory stands in for an SBOM when the image has none: the components found in the
// image, all present, with no VEX. CPE product is the component's name unless it has its own CPE.
func FromInventory(source string, comps []Package) (*Sbom, *Status) {
	s := &Sbom{Packages: map[string]*Package{}, Generates: newIDList(), RuntimeDeps: newIDList(), BuildDeps: newIDList(),
		Vulns: newIDList(), vex: map[pair]string{}, vexNotes: map[pair]string{}, stated: map[pair]string{}, matched: map[pair]bool{}, fixes: map[pair]Fix{},
		VulnInfo: map[string]*VulnInfo{}, Inventory: source}
	st := &Status{M: map[string]*pyjson.Obj{}}
	for i := range comps {
		p := comps[i]
		p.ID, p.Role = "inventory/"+p.Name, "recipe"
		if len(p.Cpes) == 0 {
			p.Cpes = []string{"cpe:2.3:a:*:" + strings.ToLower(p.Name) + ":" + p.Version + ":*:*:*:*:*:*:*"}
		}
		s.Packages[p.ID] = &p
		s.PackageOrder = append(s.PackageOrder, p.ID)
		st.set(p.ID, pyjson.O("status", "present"))
	}
	return s, st
}

// MatchTargets lists the CPEs of the components CVEs are attached to: build components
// (recipes) when the SBOM has them, otherwise the binary packages.
func (s *Sbom) MatchTargets() []CPE {
	role := "package"
	for _, id := range s.PackageOrder {
		if s.Packages[id].Role == "recipe" {
			role = "recipe"
			break
		}
	}
	var out []CPE
	for _, id := range s.PackageOrder {
		p := s.Packages[id]
		if p.Role != role {
			continue
		}
		seen := map[string]bool{}
		for _, c := range p.Cpes {
			f := strings.Split(c, ":")
			if len(f) < 6 || f[0] != "cpe" || f[1] != "2.3" {
				continue
			}
			vendor, product, version := f[3], f[4], f[5]
			if product == "" || product == "*" || version == "" || version == "*" || version == "-" {
				continue
			}
			key := vendor + ":" + product + ":" + version
			if !seen[key] {
				seen[key] = true
				out = append(out, CPE{Comp: id, Vendor: vendor, Product: product, Version: version})
			}
		}
	}
	return out
}

// AddMatch records that a version match found cve in component comp. The SBOM's own
// assessment of that pair, when it has one, is kept; otherwise the CVE counts as affected.
// info fills in what the SBOM doesn't know about the CVE.
func (s *Sbom) AddMatch(comp, cve string, info *VulnInfo) {
	if _, ok := s.Packages[comp]; !ok {
		return
	}
	ids := s.Vulns.M[comp]
	i := sort.SearchStrings(ids, cve)
	if i == len(ids) || ids[i] != cve {
		ids = append(ids, "")
		copy(ids[i+1:], ids[i:])
		ids[i] = cve
		if _, ok := s.Vulns.M[comp]; !ok {
			s.Vulns.Keys = append(s.Vulns.Keys, comp)
		}
		s.Vulns.M[comp] = ids
	}
	if _, ok := s.vex[pair{cve, comp}]; !ok {
		s.vex[pair{cve, comp}] = "affected"
		s.matched[pair{cve, comp}] = true
	}
	if info == nil {
		return
	}
	cur := s.VulnInfo[cve]
	if cur == nil {
		s.VulnInfo[cve] = info
		return
	}
	if cur.Description == "" {
		cur.Description = info.Description
	}
	if cur.Published == "" {
		cur.Published = info.Published
	}
	if len(cur.CVSS) == 0 {
		cur.CVSS, cur.CVSSOrder = info.CVSS, info.CVSSOrder
	}
}

// Matched reports whether the pair's status came from a version match, not from the SBOM.
// Listed returns each component's CVEs as [comp, cve] pairs.
func (s *Sbom) Listed() [][2]string {
	var out [][2]string
	for _, comp := range s.Vulns.Keys {
		for _, cve := range s.Vulns.M[comp] {
			out = append(out, [2]string{comp, cve})
		}
	}
	return out
}

// Fix is the upstream fix for a CVE on one component. Commit and Mainline are kernel only.
type Fix struct {
	Version, Commit          string
	Backport                 bool
	Mainline, MainlineCommit string
	Stable, StableCommit     string
}

// SetFix records the upstream fix, taken from the CVE record even for CVEs the SBOM lists.
func (s *Sbom) SetFix(comp, cve string, fix Fix) { s.fixes[pair{cve, comp}] = fix }

// FixOf is the upstream fix, zero if unknown.
func (s *Sbom) FixOf(cve, comp string) Fix { return s.fixes[pair{cve, comp}] }

func (s *Sbom) Matched(cve, comp string) bool { return s.matched[pair{cve, comp}] }
