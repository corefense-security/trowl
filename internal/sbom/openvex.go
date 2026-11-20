package sbom

import (
	"slices"
	"strings"

	"github.com/corefense-security/trowl/internal/openvex"
)

// UserVEX is a statement from the --vex file that applies to one CVE on one component.
type UserVEX struct {
	Stmt    *openvex.Statement
	Product openvex.Product // the product or subcomponent that named the component, as written
	Link    string          // how it was linked: id, purl, cpe or name
}

// UserVEXOf returns the --vex statement for the pair, or nil.
func (s *Sbom) UserVEXOf(cve, comp string) *UserVEX { return s.user[pair{cve, comp}] }

// VEXCounts says what happened to the statements of a --vex file.
type VEXCounts struct {
	Statements int
	Applied    int // linked to a component and a CVE Trowl found
	NoProduct  int // no product links to a component in the image
	NoCVE      int // the product is there but Trowl didn't find the CVE on it
}

// ApplyOpenVEX links each statement to the components it names and records it on the CVEs Trowl
// found there. It never adds a CVE. When several statements cover a pair the newest one wins, and
// a later one in the file wins a tie.
func (s *Sbom) ApplyOpenVEX(doc *openvex.Doc) VEXCounts {
	if s.user == nil {
		s.user = map[pair]*UserVEX{}
	}
	n := VEXCounts{Statements: len(doc.Statements)}
	for _, st := range doc.Statements {
		cves := st.CVEs()
		linked, applied := false, false
		for _, p := range st.Products {
			// A product with subcomponents is the image or a container, and the subcomponents
			// are its packages. Trowl scans one image, so only the packages are looked up.
			targets := p.Subcomponents
			if len(targets) == 0 {
				targets = []openvex.Product{p}
			}
			for _, t := range targets {
				comps, link := s.link(t)
				for _, comp := range comps {
					linked = true
					for _, carrier := range s.carriersOf(comp) {
						for _, cve := range cves {
							if !slices.Contains(s.Vulns.M[carrier], cve) {
								continue
							}
							k := pair{cve, carrier}
							if old := s.user[k]; old == nil || !old.Stmt.Time.After(st.Time) {
								s.user[k] = &UserVEX{Stmt: st, Product: t, Link: link}
							}
							applied = true
						}
					}
				}
			}
		}
		switch {
		case applied:
			n.Applied++
		case linked:
			n.NoCVE++
		default:
			n.NoProduct++
		}
	}
	return n
}

// link finds the components a product names. It tries the exact SBOM ID first, then the PURL,
// then the CPE, then the name and version, and stops at the first that finds any.
func (s *Sbom) link(p openvex.Product) ([]string, string) {
	keys := p.Keys()
	var out []string
	add := func(id string) {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	for _, k := range keys {
		if s.Packages[k] != nil {
			add(k)
		} else if l, ok := parseBOMLink(k); ok && l.serial == s.Serial && s.Packages[l.ref] != nil {
			add(l.ref)
		}
	}
	if len(out) > 0 {
		return out, "id"
	}
	for _, k := range keys {
		want, ok := openvex.ParsePURL(k)
		if !ok {
			continue
		}
		for _, id := range s.PackageOrder {
			if got, ok := openvex.ParsePURL(s.Packages[id].Purl); ok && got.Same(want) {
				add(id)
			}
		}
	}
	if len(out) > 0 {
		return out, "purl"
	}
	for _, k := range keys {
		want, ok := openvex.ParseCPE(k)
		if !ok {
			continue
		}
		for _, id := range s.PackageOrder {
			// A CPE Trowl made up says no more than the name, so it is left to the name match.
			if s.Packages[id].GuessedCPE {
				continue
			}
			for _, c := range s.Packages[id].Cpes {
				if got, ok := openvex.ParseCPE(c); ok && got.Same(want) {
					add(id)
				}
			}
		}
	}
	if len(out) > 0 {
		return out, "cpe"
	}
	for _, k := range keys {
		name, version, ok := openvex.NameVersion(k)
		if !ok {
			continue
		}
		for _, id := range s.PackageOrder {
			pkg := s.Packages[id]
			if strings.EqualFold(pkg.Name, name) && s.sameVersion(pkg.Version, version) {
				add(id)
			}
		}
	}
	return out, "name"
}

// sameVersion compares a component's version with a statement's. A package database keeps only
// the upstream version, so the statement's epoch and packaging revision are dropped for it.
func (s *Sbom) sameVersion(have, want string) bool {
	if want == "" || have == want {
		return true
	}
	return s.Inventory != "" && have == upstreamVersion(want)
}

// upstreamVersion drops an epoch and a packaging revision, so 1:3.0.15-1~deb12u1 becomes 3.0.15.
func upstreamVersion(v string) string {
	if _, rest, ok := strings.Cut(v, ":"); ok {
		v = rest
	}
	if i := strings.LastIndex(v, "-"); i > 0 {
		v = v[:i]
	}
	return v
}

// carriersOf lists the components whose CVEs a statement on comp covers. That is comp itself and,
// for a binary package, the recipe that builds it, since Yocto files CVEs under the recipe.
func (s *Sbom) carriersOf(comp string) []string {
	out := []string{comp}
	for _, recipe := range s.Generates.Keys {
		if slices.Contains(s.Generates.M[recipe], comp) {
			out = append(out, recipe)
		}
	}
	return out
}

// defiesUser reports whether Trowl's kernel verdict contradicts a --vex statement. Only a claim
// about the code being built can be contradicted. Other justifications, such as an inline
// mitigation, say something Trowl doesn't check.
func defiesUser(st *openvex.Statement, trowl string) bool {
	switch st.Status {
	case "affected":
		return trowl == "not_affected"
	case "not_affected":
		codeClaim := st.Justification == "vulnerable_code_not_present" || st.Justification == "component_not_present"
		return codeClaim && trowl == "affected"
	}
	return false
}

func firstKey(p openvex.Product) string {
	if k := p.Keys(); len(k) > 0 {
		return k[0]
	}
	return ""
}

// ExportVEX writes one statement per CVE on each component that may ship. A pair the --vex file
// covered keeps that file's statement as given. Every other pair gets Trowl's status. A component
// with no PURL and no real CPE can't be named, so it is left out and counted.
func ExportVEX(sb *Sbom, status *Status) (out []*openvex.Statement, unnamed int) {
	for _, comp := range sb.Vulns.Keys {
		pkg := sb.Packages[comp]
		if pkg == nil || !MayShip(or(shippedOfRecipe, status.Of(comp), "unknown")) {
			continue
		}
		product, named := productOf(pkg)
		for _, cve := range sb.Vulns.M[comp] {
			st, user, a := carrierStatus(sb, cve, comp)
			if user != nil {
				out = append(out, &openvex.Statement{Vulnerability: openvex.Vulnerability{Name: cve},
					Timestamp: user.Stmt.Timestamp, Products: []openvex.Product{{ID: firstKey(user.Product),
						Identifiers: user.Product.Identifiers}},
					Status: user.Stmt.Status, Justification: user.Stmt.Justification, Impact: user.Stmt.Impact,
					Action: user.Stmt.Action, Notes: user.Stmt.Notes})
				continue
			}
			if !named {
				unnamed++
				continue
			}
			s := &openvex.Statement{Vulnerability: openvex.Vulnerability{Name: cve}, Products: []openvex.Product{product}}
			trowlStatement(s, sb, pkg, cve, comp, st, a)
			out = append(out, s)
		}
	}
	return out, unnamed
}

// productOf names a component by its PURL, else by its CPE. A CPE Trowl made up isn't used,
// since no other tool would write it.
func productOf(pkg *Package) (openvex.Product, bool) {
	ids := map[string]string{}
	if pkg.Purl != "" {
		ids["purl"] = pkg.Purl
	}
	if len(pkg.Cpes) > 0 && !pkg.GuessedCPE {
		ids["cpe23"] = pkg.Cpes[0]
	}
	id := ids["purl"]
	if id == "" {
		id = ids["cpe23"]
	}
	if id == "" {
		return openvex.Product{}, false
	}
	return openvex.Product{ID: id, Identifiers: ids}, true
}

// Yocto's cve-check notes that say the code or the package isn't there.
var noteJustification = map[string]string{
	ConfigNote:                "vulnerable_code_not_present",
	"not-applicable-platform": "component_not_present",
	"cpe-incorrect":           "component_not_present",
}

// trowlStatement fills in Trowl's status, with the reason OpenVEX asks for.
func trowlStatement(s *openvex.Statement, sb *Sbom, pkg *Package, cve, comp, st string, a *Assessment) {
	notes := sb.VexNotes(cve, comp)
	switch st {
	case "affected":
		s.Status = "affected"
		if fix := sb.FixOf(cve, comp); fix.Version != "" {
			s.Action = "Update " + pkg.Name + " to " + fix.Version + " or later."
		} else {
			s.Action = "No fixed version is known. Follow the advisory."
		}
		switch {
		case a != nil:
			s.Notes = a.Detail
		case sb.Matched(cve, comp):
			s.Notes = "Version " + pkg.Version + " is in the affected range."
		}
	case "not_affected":
		s.Status = "not_affected"
		switch {
		case a != nil && a.Status == "not_affected":
			s.Justification, s.Notes = a.Justification, a.Detail
		case sb.codeAbsent[pair{cve, comp}]:
			s.Justification = "vulnerable_code_not_present"
		case noteJustification[notes] != "":
			s.Justification, s.Notes = noteJustification[notes], notes
		default:
			s.Impact = "The SBOM marks it not affected."
			if notes != "" {
				s.Impact = "The SBOM marks it not affected: " + notes
			}
		}
	case "fixed":
		s.Status, s.Notes = "fixed", notes
	case "review":
		s.Status = "under_investigation"
		if a != nil {
			s.Notes = a.Detail
		}
	case "under_investigation":
		s.Status, s.Notes = "under_investigation", notes
	default:
		s.Status, s.Notes = "under_investigation", "The SBOM lists this CVE without a status."
	}
}
