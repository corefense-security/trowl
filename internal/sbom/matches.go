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
		Vulns: newIDList(), vex: map[pair]string{}, vexNotes: map[pair]string{}, stated: map[pair]string{}, matched: map[pair]bool{}, nameOnly: map[pair]bool{}, fixes: map[pair]Fix{},
		assessed: map[pair]*Assessment{}, VulnInfo: map[string]*VulnInfo{}, Inventory: source}
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

// MarkNameOnly records that a version match rests on the package name alone: the SBOM gives no
// vendor, so the CVE may be for another product of the same name. A CVE the SBOM lists itself
// isn't affected.
func (s *Sbom) MarkNameOnly(comp, cve string) {
	if s.Matched(cve, comp) {
		s.nameOnly[pair{cve, comp}] = true
	}
}

func (s *Sbom) NameOnly(cve, comp string) bool { return s.nameOnly[pair{cve, comp}] }

// Assessment is trowl's own VEX judgement of a CVE on a component, from something it checked
// rather than from the SBOM.
type Assessment struct {
	Status        string // affected, not_affected or under_investigation
	Justification string // why not_affected, in OpenVEX's words
	Detail        string // what was found, in a sentence
	Short         string // the same in a few words, such as "file not in tree"
	Evidence      []*pyjson.Obj
	Stated        string // the SBOM's status for the pair, "" if it gave none
	StatedNotes   string // the SBOM's note on that status, such as not-applicable-config
	Defies        bool   // the SBOM said otherwise
}

// Assess records a. A decided status replaces the one the pair had. under_investigation leaves
// the VEX status as it was; the report shows such a pair as Needs review (see reviewed).
func (s *Sbom) Assess(cve, comp string, a *Assessment) {
	k := pair{cve, comp}
	s.assessed[k] = a
	switch a.Status {
	case "not_affected":
		s.vex[k], s.vexNotes[k] = "not_affected", ConfigNote
	case "affected":
		if s.vex[k] != "affected" {
			s.vex[k] = "affected"
			delete(s.vexNotes, k)
		}
	}
}

// AssessmentOf is trowl's judgement of the pair, nil without one.
func (s *Sbom) AssessmentOf(cve, comp string) *Assessment { return s.assessed[pair{cve, comp}] }

// ConfigNote is the VEX note for code the kernel config leaves out, in Yocto's words.
const ConfigNote = "not-applicable-config"

// KernelComponents lists the components that are the Linux kernel.
func (s *Sbom) KernelComponents() []string {
	var out []string
	for _, id := range s.PackageOrder {
		if s.Packages[id].IsKernel() {
			out = append(out, id)
		}
	}
	return out
}

// IsKernel reports whether the package is the Linux kernel, by its CPE.
func (p *Package) IsKernel() bool {
	for _, c := range p.Cpes {
		if strings.Contains(c, ":linux_kernel:") {
			return true
		}
	}
	return false
}

// AssessesKernel reports whether the SBOM carries a CVE scanner's verdicts on the kernel. Only a
// scanner states "affected": a plain Yocto SBOM lists the recipe's own CVE_STATUS lines, all fixed
// or not affected, and says nothing about the thousands of CVEs nobody wrote a line for.
func (s *Sbom) AssessesKernel() bool {
	for _, comp := range s.KernelComponents() {
		for _, cve := range s.Vulns.M[comp] {
			if s.Vex(cve, comp) == "affected" && !s.Matched(cve, comp) {
				return true
			}
		}
	}
	return false
}
