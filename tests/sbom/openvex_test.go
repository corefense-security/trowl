package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corefense-security/trowl/internal/openvex"
	"github.com/corefense-security/trowl/internal/sbom"
)

// OpenVEX files in testdata/openvex are written the way Trivy, Grype, older tools and a Yocto
// team's own triage write them.
const vexDir = "testdata/openvex"

func readVEX(t *testing.T, name string) *openvex.Doc {
	t.Helper()
	doc, err := openvex.Read(filepath.Join(vexDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// cdxWithCVEs loads the meta-cyclonedx SBOM with openssl given a PURL, and lists a CVE on each
// component as a version match would.
func cdxWithCVEs(t *testing.T) *sbom.Sbom {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(split, "bom.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(raw), `"name": "openssl"`, `"name": "openssl", "purl": "pkg:generic/openssl@3.5.4"`, 1)
	if text == string(raw) {
		t.Fatal("bom.json has no openssl component to give a PURL")
	}
	p := filepath.Join(t.TempDir(), "bom.json")
	os.WriteFile(p, []byte(text), 0o644)
	sb := load(t, p)
	sb.AddMatch("openssl", "CVE-2025-1001", nil)
	sb.AddMatch("busybox", "CVE-2025-1002", nil)
	sb.AddMatch("linux-yocto", "CVE-2025-1003", nil)
	return sb
}

// Each tool names packages its own way. Every file links to the component it means.
func TestOpenVEXFromOtherTools(t *testing.T) {
	for _, c := range []struct {
		file, cve, comp, status, link string
	}{
		// A PURL whose qualifiers Trowl's component lacks.
		{"trivy.openvex.json", "CVE-2025-1001", "openssl", "not_affected", "purl"},
		// The image as product and the package as a subcomponent, named by a GHSA with a CVE alias.
		{"grype.openvex.json", "CVE-2025-1002", "busybox", "fixed", "cpe"},
		// v0.0.x strings, with the product given as a BOM-Link into the SBOM.
		{"v0.0.2.openvex.json", "CVE-2025-1003", "linux-yocto", "affected", "id"},
	} {
		sb := cdxWithCVEs(t)
		n := sb.ApplyOpenVEX(readVEX(t, c.file))
		if n.Applied != 1 || n.NoCVE != 0 || n.NoProduct != 0 {
			t.Errorf("%s: counts %+v", c.file, n)
		}
		u := sb.UserVEXOf(c.cve, c.comp)
		if u == nil || u.Stmt.Status != c.status || u.Link != c.link {
			t.Errorf("%s: %s on %s is %+v, want %s by %s", c.file, c.cve, c.comp, u, c.status, c.link)
		}
	}
}

// A Yocto team's triage file names a binary package and the recipe's CPE. Both reach the recipe,
// which carries the CVEs, and the file's statuses replace the SBOM's own.
func TestOpenVEXOnYoctoSpdx22(t *testing.T) {
	sb := load(t, yocto)
	n := sb.ApplyOpenVEX(readVEX(t, "yocto.openvex.json"))
	if n.Applied != 2 {
		t.Errorf("counts %+v", n)
	}
	for _, c := range []struct{ cve, status, link string }{
		{"CVE-2022-48174", "not_affected", "name"},       // through busybox-syslog to its recipe
		{"CVE-2023-42363", "under_investigation", "cpe"}, // the SBOM says fixed
	} {
		u := sb.UserVEXOf(c.cve, recipe)
		if u == nil || u.Stmt.Status != c.status || u.Link != c.link {
			t.Errorf("%s is %+v, want %s by %s", c.cve, u, c.status, c.link)
		}
	}
	if sb.Vex("CVE-2023-42363", recipe) != "fixed" {
		t.Error("the SBOM's own status is kept beside the file's")
	}
	u := sb.UserVEXOf("CVE-2022-48174", recipe)
	if u.Stmt.Impact != "The image doesn't run the affected applet." || u.Stmt.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("the statement's reason is lost: %+v", u.Stmt)
	}
}

// A file for another image links to nothing, and the counts say so.
func TestOpenVEXForAnotherImage(t *testing.T) {
	sb := cdxWithCVEs(t)
	n := sb.ApplyOpenVEX(readVEX(t, "other-image.openvex.json"))
	if n.Applied != 0 || n.NoProduct != 1 {
		t.Errorf("counts %+v", n)
	}
	if sb.UserVEXOf("CVE-2025-1001", "openssl") != nil {
		t.Error("libssl3 from Debian isn't this image's openssl")
	}
}

// openvex.Is tells an OpenVEX file from a CycloneDX VEX, which --vex also takes.
func TestOpenVEXIsDetected(t *testing.T) {
	for _, f := range []string{"trivy.openvex.json", "v0.0.2.openvex.json"} {
		raw, _ := os.ReadFile(filepath.Join(vexDir, f))
		if !openvex.Is(raw) {
			t.Errorf("%s isn't seen as OpenVEX", f)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(split, "vex.json"))
	if openvex.Is(raw) {
		t.Error("a CycloneDX VEX is seen as OpenVEX")
	}
}
