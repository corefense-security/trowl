package sbom

import (
	"strings"
	"testing"
	"time"

	"github.com/corefense-security/trowl/internal/openvex"
	"github.com/corefense-security/trowl/internal/pyjson"
)

func stmt(cve, product, status string, at int) *openvex.Statement {
	return &openvex.Statement{Vulnerability: openvex.Vulnerability{Name: cve}, Products: []openvex.Product{{ID: product}},
		Status: status, Time: time.Date(2026, time.Month(at), 1, 0, 0, 0, 0, time.UTC)}
}

func vexSbom() *Sbom {
	sb, _ := FromInventory("opkg", []Package{{Name: "openssl", Version: "3.0.15"},
		{Name: "busybox", Version: "1.36.1", Cpes: []string{"cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*"}}})
	sb.Packages["inventory/openssl"].Purl = "pkg:yocto/core/openssl@3.0.15"
	sb.AddMatch("inventory/openssl", "CVE-1", nil)
	sb.AddMatch("inventory/openssl", "CVE-2", nil)
	sb.AddMatch("inventory/busybox", "CVE-3", nil)
	return sb
}

// Each statement is linked by the most exact identifier it shares with a component, and the
// newest statement on a pair wins.
func TestApplyOpenVEX(t *testing.T) {
	sb := vexSbom()
	n := sb.ApplyOpenVEX(&openvex.Doc{Statements: []*openvex.Statement{
		stmt("CVE-1", "pkg:yocto/core/openssl@3.0.15", "not_affected", 3),
		stmt("CVE-1", "openssl@3.0.15", "affected", 1), // older, so it loses
		stmt("CVE-3", "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*", "fixed", 1),
		stmt("CVE-9", "pkg:yocto/core/openssl@3.0.15", "affected", 1), // a CVE Trowl didn't find
		stmt("CVE-1", "pkg:deb/debian/zlib@1.3", "fixed", 1),          // not in the image
	}})
	if n.Applied != 3 || n.NoCVE != 1 || n.NoProduct != 1 {
		t.Errorf("counts %+v", n)
	}
	if u := sb.UserVEXOf("CVE-1", "inventory/openssl"); u == nil || u.Stmt.Status != "not_affected" || u.Link != "purl" {
		t.Errorf("CVE-1 %+v", u)
	}
	if u := sb.UserVEXOf("CVE-3", "inventory/busybox"); u == nil || u.Link != "cpe" {
		t.Errorf("CVE-3 %+v", u)
	}
	if sb.UserVEXOf("CVE-2", "inventory/openssl") != nil {
		t.Error("CVE-2 has no statement")
	}
	if slicesHas(sb.Vulns.M["inventory/openssl"], "CVE-9") {
		t.Error("a statement added a CVE")
	}
}

func slicesHas(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// A package database keeps upstream versions, so a Debian version with an epoch and a revision
// still finds the component by name.
func TestApplyOpenVEXByNameForPackageDatabase(t *testing.T) {
	sb, _ := FromInventory("dpkg", []Package{{Name: "openssl", Version: "3.0.15"}})
	sb.AddMatch("inventory/openssl", "CVE-1", nil)
	sb.ApplyOpenVEX(&openvex.Doc{Statements: []*openvex.Statement{
		stmt("CVE-1", "pkg:deb/debian/openssl@1:3.0.15-1~deb12u1", "fixed", 1)}})
	if u := sb.UserVEXOf("CVE-1", "inventory/openssl"); u == nil || u.Link != "name" {
		t.Errorf("got %+v", u)
	}
}

// Yocto files CVEs under the recipe, but a statement may name the binary package.
func TestApplyOpenVEXReachesTheRecipe(t *testing.T) {
	sb, _ := FromInventory("opkg", []Package{{Name: "busybox", Version: "1.36.1"}})
	sb.AddMatch("inventory/busybox", "CVE-1", nil)
	pkg := &Package{ID: "pkg/busybox-udhcpc", Name: "busybox-udhcpc", Version: "1.36.1", Role: "package",
		Purl: "pkg:yocto/core/busybox-udhcpc@1.36.1"}
	sb.Packages[pkg.ID] = pkg
	sb.PackageOrder = append(sb.PackageOrder, pkg.ID)
	sb.Generates.add("inventory/busybox", pkg.ID)
	sb.ApplyOpenVEX(&openvex.Doc{Statements: []*openvex.Statement{
		{Vulnerability: openvex.Vulnerability{Name: "CVE-1"}, Status: "not_affected",
			Products: []openvex.Product{{ID: "pkg:oci/image", Subcomponents: []openvex.Product{{ID: pkg.Purl}}}}}}})
	if u := sb.UserVEXOf("CVE-1", "inventory/busybox"); u == nil || u.Link != "purl" {
		t.Errorf("got %+v", u)
	}
}

// A VEX file's status decides the row even where Trowl's kernel check says otherwise. Trowl only
// flags the disagreement.
func TestUserVEXBeatsTrowl(t *testing.T) {
	sb, st := FromInventory("opkg", nil)
	k := &Package{ID: "inventory/linux", Name: "linux", Version: "6.6.1", Role: "recipe",
		Cpes: []string{"cpe:2.3:o:linux:linux_kernel:6.6.1:*:*:*:*:*:*:*"}}
	sb.Packages[k.ID] = k
	sb.PackageOrder = append(sb.PackageOrder, k.ID)
	st.set(k.ID, pyjson.O("status", "present"))
	sb.AddMatch(k.ID, "CVE-1", nil)
	sb.Assess("CVE-1", k.ID, &Assessment{Status: "not_affected", Justification: "vulnerable_code_not_present"})
	sb.ApplyOpenVEX(&openvex.Doc{Statements: []*openvex.Statement{
		stmt("CVE-1", "cpe:2.3:o:linux:linux_kernel:6.6.1:*:*:*:*:*:*:*", "affected", 1)}})
	status, user, a := carrierStatus(sb, "CVE-1", k.ID)
	if status != "affected" || user == nil || !defiesUser(user.Stmt, a.Status) {
		t.Errorf("status %s, user %v", status, user)
	}
}

func TestDefiesUser(t *testing.T) {
	for _, c := range []struct {
		status, justification, trowl string
		want                         bool
	}{
		{"affected", "", "not_affected", true},
		{"affected", "", "under_investigation", false},
		{"not_affected", "vulnerable_code_not_present", "affected", true},
		{"not_affected", "component_not_present", "affected", true},
		{"not_affected", "inline_mitigations_already_exist", "affected", false}, // Trowl doesn't check mitigations
		{"fixed", "", "affected", false},
	} {
		got := defiesUser(&openvex.Statement{Status: c.status, Justification: c.justification}, c.trowl)
		if got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

// The export keeps a VEX file's statement as given and gives every other pair Trowl's status.
// A component Trowl can't name is left out and counted.
func TestExportVEX(t *testing.T) {
	sb := vexSbom()
	sb.SetFix("inventory/openssl", "CVE-2", Fix{Version: "3.0.16"})
	given := stmt("CVE-1", "pkg:yocto/core/openssl@3.0.15", "not_affected", 1)
	given.Justification = "inline_mitigations_already_exist"
	sb.ApplyOpenVEX(&openvex.Doc{Statements: []*openvex.Statement{given}})
	_, st := FromInventory("opkg", []Package{{Name: "openssl"}, {Name: "busybox"}})
	out, unnamed := ExportVEX(sb, st)
	by := map[string]*openvex.Statement{}
	for _, s := range out {
		by[s.Vulnerability.Name] = s
	}
	if s := by["CVE-1"]; s == nil || s.Status != "not_affected" || s.Justification != "inline_mitigations_already_exist" {
		t.Errorf("CVE-1 %+v", s)
	}
	if s := by["CVE-2"]; s == nil || s.Status != "affected" || s.Action != "Update openssl to 3.0.16 or later." ||
		s.Products[0].ID != "pkg:yocto/core/openssl@3.0.15" {
		t.Errorf("CVE-2 %+v", s)
	}
	if s := by["CVE-3"]; s == nil || s.Products[0].ID != "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*" {
		t.Errorf("CVE-3 %+v", s)
	}
	if unnamed != 0 {
		t.Errorf("unnamed %d", unnamed)
	}

	// A package database entry has only a made-up CPE, so it can't be named.
	plain, pst := FromInventory("opkg", []Package{{Name: "zlib", Version: "1.3"}})
	plain.AddMatch("inventory/zlib", "CVE-4", nil)
	if out, unnamed := ExportVEX(plain, pst); len(out) != 0 || unnamed != 1 {
		t.Errorf("got %d statements, %d unnamed", len(out), unnamed)
	}
}

// Yocto's CPEs often have no vendor. They still link by CPE, unlike the ones Trowl makes up.
func TestApplyOpenVEXVendorlessCPE(t *testing.T) {
	sb, _ := FromInventory("opkg", []Package{{Name: "glibc", Version: "2.39+git",
		Cpes: []string{"cpe:2.3:*:*:glibc:2.39:*:*:*:*:*:*:*"}}, {Name: "zlib", Version: "1.3.1"}})
	sb.AddMatch("inventory/glibc", "CVE-1", nil)
	sb.AddMatch("inventory/zlib", "CVE-2", nil)
	sb.ApplyOpenVEX(&openvex.Doc{Statements: []*openvex.Statement{
		stmt("CVE-1", "cpe:2.3:a:gnu:glibc:2.39:*:*:*:*:*:*:*", "fixed", 1),
		stmt("CVE-2", "cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*", "fixed", 1)}})
	if u := sb.UserVEXOf("CVE-1", "inventory/glibc"); u == nil || u.Link != "cpe" {
		t.Errorf("glibc %+v", u)
	}
	if u := sb.UserVEXOf("CVE-2", "inventory/zlib"); u == nil || u.Link != "name" {
		t.Errorf("zlib, whose CPE Trowl made up, %+v", u)
	}
}

// kernelSbom has a kernel with CVE-1 and CVE-2, which Trowl found not compiled and compiled, and
// a userland zlib with CVE-3.
func kernelSbom() (*Sbom, *Status) {
	sb, st := FromInventory("opkg", []Package{{Name: "zlib", Version: "1.3.1",
		Cpes: []string{"cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*"}}})
	k := &Package{ID: "inventory/linux", Name: "linux", Version: "6.6.1", Role: "recipe",
		Cpes: []string{"cpe:2.3:o:linux:linux_kernel:6.6.1:*:*:*:*:*:*:*"}}
	sb.Packages[k.ID] = k
	sb.PackageOrder = append(sb.PackageOrder, k.ID)
	st.set(k.ID, pyjson.O("status", "present"))
	sb.AddMatch(k.ID, "CVE-1", nil)
	sb.AddMatch(k.ID, "CVE-2", nil)
	sb.AddMatch("inventory/zlib", "CVE-3", nil)
	sb.Assess("CVE-1", k.ID, &Assessment{Status: "not_affected", Justification: "vulnerable_code_not_present", Detail: "Not compiled"})
	sb.Assess("CVE-2", k.ID, &Assessment{Status: "affected", Detail: "Compiled"})
	return sb, st
}

// --override lets Trowl's kernel verdict replace a file statement it contradicts. A statement
// Trowl doesn't contradict and every userland statement keep the file's status.
func TestOverride(t *testing.T) {
	sb, st := kernelSbom()
	kernel := "cpe:2.3:o:linux:linux_kernel:6.6.1:*:*:*:*:*:*:*"
	mitigated := stmt("CVE-2", kernel, "not_affected", 1)
	mitigated.Justification = "inline_mitigations_already_exist"
	sb.ApplyOpenVEX(&openvex.Doc{Statements: []*openvex.Statement{
		stmt("CVE-1", kernel, "affected", 1),
		mitigated,
		stmt("CVE-3", "cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*", "fixed", 1),
	}})
	for _, override := range []bool{false, true} {
		sb.Override = override
		got := map[string]string{}
		for _, c := range [][2]string{{"CVE-1", "inventory/linux"}, {"CVE-2", "inventory/linux"}, {"CVE-3", "inventory/zlib"}} {
			got[c[0]], _, _ = carrierStatus(sb, c[0], c[1])
		}
		want := map[string]string{"CVE-1": "affected", "CVE-2": "not_affected", "CVE-3": "fixed"}
		if override {
			want["CVE-1"] = "not_affected" // Trowl found it not compiled
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("override %v: %s is %s, want %s", override, k, got[k], v)
			}
		}
	}
	if sb.CountOverridden() != 1 {
		t.Errorf("overridden %d", sb.CountOverridden())
	}
	out, _ := ExportVEX(sb, st)
	for _, s := range out {
		if s.Vulnerability.Name == "CVE-1" && (s.Status != "not_affected" ||
			!strings.HasPrefix(s.Notes, "Trowl's kernel check overrides the VEX file, which said affected.")) {
			t.Errorf("CVE-1 exported as %+v", s)
		}
		if s.Vulnerability.Name == "CVE-2" && s.Justification != "inline_mitigations_already_exist" {
			t.Errorf("CVE-2 exported as %+v", s)
		}
	}
}

// A CycloneDX VEX file's statements become file statements, with their justification in OpenVEX's
// words, so --override treats them like an OpenVEX file's.
func TestCycloneDXFileStatement(t *testing.T) {
	sb, _ := kernelSbom()
	k := pair{"CVE-2", "inventory/linux"}
	sb.vex[k] = "not_affected"
	sb.fileStatement(k, "code_not_present", "STATE: Ignored")
	u := sb.UserVEXOf("CVE-2", "inventory/linux")
	if u == nil || u.Stmt.Status != "not_affected" || u.Stmt.Justification != "vulnerable_code_not_present" ||
		u.Product.ID != "cpe:2.3:o:linux:linux_kernel:6.6.1:*:*:*:*:*:*:*" {
		t.Fatalf("got %+v", u)
	}
	if st, _, _ := carrierStatus(sb, "CVE-2", "inventory/linux"); st != "not_affected" {
		t.Errorf("without --override the file decides, got %s", st)
	}
	sb.Override = true
	if st, _, _ := carrierStatus(sb, "CVE-2", "inventory/linux"); st != "affected" {
		t.Errorf("with --override Trowl's compiled verdict decides, got %s", st)
	}
}
