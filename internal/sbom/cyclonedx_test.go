package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// buildroot is shaped like utils/generate-cyclonedx output.
const buildroot = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {
    "component": {"bom-ref": "buildroot", "name": "buildroot", "version": "2025.02", "type": "firmware"},
    "tools": {"components": [{"type": "application", "name": "Buildroot generate-cyclonedx"}]}
  },
  "components": [
    {"bom-ref": "busybox", "type": "library", "name": "busybox", "version": "1.37.0",
     "cpe": "cpe:2.3:a:busybox:busybox:1.37.0:*:*:*:*:*:*:*",
     "pedigree": {"patches": [{"type": "unofficial", "resolves": [{"type": "security", "id": "CVE-2023-42366", "name": "CVE-2023-42366"}]}]}},
    {"bom-ref": "host-m4", "type": "library", "scope": "excluded", "name": "m4", "version": "1.4.19",
     "cpe": "cpe:2.3:a:gnu:m4:1.4.19:*:*:*:*:*:*:*"},
    {"bom-ref": "linux", "type": "library", "name": "linux", "version": "6.12.10",
     "cpe": "cpe:2.3:o:linux:linux_kernel:6.12.10:*:*:*:*:*:*:*"}
  ],
  "dependencies": [
    {"ref": "buildroot", "dependsOn": ["busybox", "linux"]},
    {"ref": "busybox", "dependsOn": ["host-m4"]}
  ],
  "vulnerabilities": [
    {"id": "CVE-2023-42366", "analysis": {"state": "resolved_with_pedigree", "detail": "ignored by Buildroot"},
     "affects": [{"ref": "busybox"}]},
    {"id": "CVE-2024-0001", "analysis": {"state": "in_triage"}, "affects": [{"ref": "host-m4"}]},
    {"id": "CVE-2024-0002", "affects": [{"ref": "linux"}],
     "ratings": [{"method": "CVSSv31", "score": 7.8, "severity": "high", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}],
     "description": "a kernel bug"},
    {"id": "GHSA-xxxx", "references": [{"id": "CVE-2024-0003"}],
     "analysis": {"state": "not_affected", "justification": "code_not_present"}, "affects": [{"ref": "busybox"}]}
  ]
}`

func loadText(t *testing.T, text string) *Sbom {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bom.json")
	os.WriteFile(p, []byte(text), 0o644)
	sb, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func TestCycloneDXBuildroot(t *testing.T) {
	sb := loadText(t, buildroot)
	if sb.Format != "CycloneDX 1.6" || sb.Producer != "Buildroot generate-cyclonedx" || sb.Name != "buildroot" {
		t.Errorf("format %q, producer %q, name %q", sb.Format, sb.Producer, sb.Name)
	}
	if want := []string{"busybox", "host-m4", "linux"}; !reflect.DeepEqual(sb.PackageOrder, want) {
		t.Errorf("packages %v", sb.PackageOrder)
	}
	if !sb.Packages["host-m4"].BuildOnly || sb.Packages["busybox"].BuildOnly {
		t.Error("only host-m4 is build-only")
	}
	if !sb.Packages["linux"].IsKernel() {
		t.Error("linux is the kernel")
	}
	for _, c := range []struct{ cve, comp, vex string }{
		{"CVE-2023-42366", "busybox", "fixed"},
		{"CVE-2024-0001", "host-m4", "under_investigation"},
		{"CVE-2024-0002", "linux", ""},
		{"CVE-2024-0003", "busybox", "not_affected"},
	} {
		if got := sb.Vex(c.cve, c.comp); got != c.vex {
			t.Errorf("%s on %s: %q, want %q", c.cve, c.comp, got, c.vex)
		}
	}
	if got := sb.VexNotes("CVE-2024-0003", "busybox"); got != "code_not_present." {
		t.Errorf("notes %q", got)
	}
	if want := []string{"CVE-2023-42366", "CVE-2024-0003"}; !reflect.DeepEqual(sb.Vulns.M["busybox"], want) {
		t.Errorf("busybox CVEs %v", sb.Vulns.M["busybox"])
	}
	if c := sb.VulnInfo["CVE-2024-0002"].CVSS["3"]; c == nil || c.Score != 7.8 {
		t.Errorf("CVSS %v", c)
	}
	if !reflect.DeepEqual(sb.BuildDeps.M["busybox"], []string{"host-m4"}) || len(sb.RuntimeDeps.M["busybox"]) != 0 {
		t.Errorf("build deps %v runtime deps %v", sb.BuildDeps.M, sb.RuntimeDeps.M)
	}
	if got := sb.MatchTargets(); len(got) != 3 {
		t.Errorf("targets %v", got)
	}

	cmp := Compare(sb, t.TempDir(), false)
	for id, want := range map[string]string{"busybox": "no-files", "host-m4": "build-only", "linux": "no-files"} {
		if got := cmp.Status.Of(id); got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
	if len(cmp.NotPresent) != 1 {
		t.Errorf("not present %v", cmp.NotPresent)
	}
	shipped := map[string]string{}
	for _, r := range BuildCVEs(sb, cmp.Status) {
		shipped[r.G("id").(string)] = r.G("shipped").(string)
	}
	if shipped["CVE-2024-0001"] != "build" || shipped["CVE-2024-0002"] != "unknown" {
		t.Errorf("shipped %v", shipped)
	}
}

func TestCycloneDXFilePresence(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/bin/tool"), []byte("tool"), 0o755)
	sum := sha256.Sum256([]byte("tool"))
	good := hex.EncodeToString(sum[:])
	sb := loadText(t, `{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
	  {"bom-ref": "a", "name": "a", "version": "1", "components": [
	    {"type": "file", "name": "/usr/bin/tool", "hashes": [{"alg": "SHA-256", "content": "`+good+`"}]}]},
	  {"bom-ref": "b", "name": "b", "version": "1", "components": [
	    {"type": "file", "name": "/usr/bin/tool", "hashes": [{"alg": "SHA-256", "content": "00"}]}]},
	  {"bom-ref": "c", "name": "c", "version": "1", "components": [{"type": "file", "name": "/usr/bin/gone"}]}]}`)
	cmp := Compare(sb, root, false)
	for id, want := range map[string]string{"a": "present", "b": "modified", "c": "absent"} {
		if got := cmp.Status.Of(id); got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
}

func TestCycloneDXToolsList(t *testing.T) {
	sb := loadText(t, `{"bomFormat": "CycloneDX", "specVersion": "1.4",
	  "metadata": {"tools": [{"vendor": "anchore", "name": "syft"}]}, "components": [{"name": "x", "version": "1"}]}`)
	if sb.Producer != "syft" || sb.PackageOrder[0] != "x@1" {
		t.Errorf("producer %q, packages %v", sb.Producer, sb.PackageOrder)
	}
}

// Load refuses vulnerabilities in the SBOM that it can't read. An analysis may be left out
// here because a scanner lists what it found without judging it.
func TestCycloneDXEmbeddedNeedsFields(t *testing.T) {
	for name, c := range map[string]struct{ vuln, want string }{
		"no id":         {`{"affects": [{"ref": "a"}]}`, "vulnerability 1 has no id"},
		"no affects":    {`{"id": "CVE-1"}`, "has no affects"},
		"empty ref":     {`{"id": "CVE-1", "affects": [{"ref": ""}]}`, "affects entry with no ref"},
		"no state":      {`{"id": "CVE-1", "analysis": {}, "affects": [{"ref": "a"}]}`, "analysis with no state"},
		"unknown state": {`{"id": "CVE-1", "analysis": {"state": "fine"}, "affects": [{"ref": "a"}]}`, `unknown analysis state "fine"`},
	} {
		p := filepath.Join(t.TempDir(), "bom.json")
		os.WriteFile(p, []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:abc",
		  "components": [{"bom-ref": "a", "name": "a", "version": "1"}], "vulnerabilities": [`+c.vuln+`]}`), 0o644)
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// Refs to the root, to an unlisted component or to another BOM are skipped and counted.
// Buildroot writes ignored CVEs for virtual packages it drops from the components.
func TestCycloneDXEmbeddedSkippedRefs(t *testing.T) {
	sb := loadText(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:abc",
	  "metadata": {"component": {"bom-ref": "img", "name": "img"}},
	  "components": [{"bom-ref": "a", "name": "a", "version": "1"}],
	  "vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "resolved"},
	    "affects": [{"ref": "img"}, {"ref": "virtual-pkg"}, {"ref": "urn:cdx:other/1#a"},
	      {"ref": "urn:cdx:abc/2#a"}, {"ref": "urn:cdx:abc/1#a"}]}]}`)
	if sb.Vex("CVE-1", "a") != "fixed" || len(sb.Vulns.M["img"]) != 0 || sb.VEXSkipped != 4 {
		t.Errorf("vex %q root %v skipped %d", sb.Vex("CVE-1", "a"), sb.Vulns.M["img"], sb.VEXSkipped)
	}
}

// Without a serial a BOM-Link can't be checked so it is skipped. A plain ref still applies.
func TestCycloneDXEmbeddedLinkWithoutSerial(t *testing.T) {
	sb := loadText(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [{"bom-ref": "a", "name": "a", "version": "1"}, {"bom-ref": "b", "name": "b", "version": "1"}],
	  "vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "resolved"},
	    "affects": [{"ref": "urn:cdx:abc/1#a"}, {"ref": "b"}]}]}`)
	if sb.Vex("CVE-1", "a") != "" || sb.Vex("CVE-1", "b") != "fixed" || sb.VEXSkipped != 1 {
		t.Errorf("a %q b %q skipped %d", sb.Vex("CVE-1", "a"), sb.Vex("CVE-1", "b"), sb.VEXSkipped)
	}
}

// Components nested under the root component are read like top-level ones.
func TestCycloneDXRootChildren(t *testing.T) {
	sb := loadText(t, `{"bomFormat": "CycloneDX", "specVersion": "1.5",
	  "metadata": {"component": {"bom-ref": "app", "name": "app",
	    "components": [{"bom-ref": "zlib", "name": "zlib", "version": "1.3.1"}]}},
	  "components": [{"bom-ref": "openssl", "name": "openssl", "version": "3.5.4"}]}`)
	if want := []string{"openssl", "zlib"}; !reflect.DeepEqual(sb.PackageOrder, want) {
		t.Errorf("packages %v", sb.PackageOrder)
	}
}

// A CycloneDX document of the wrong shape is refused.
func TestCycloneDXWrongShape(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bom.json")
	os.WriteFile(p, []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": {}}`), 0o644)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "not valid CycloneDX JSON") {
		t.Errorf("got %v", err)
	}
}
