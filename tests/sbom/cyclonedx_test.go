package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corefense-security/trowl/internal/sbom"
)

// split is a small meta-cyclonedx pair. bom.json has the components and vex.json has the
// statements. Each statement points at the BOM by BOM-Link.
const split = "testdata/cyclonedx-split"

const serial = "11111111-2222-3333-4444-555555555555"

// writeVEX writes a VEX file with one statement per ref and returns its path.
func writeVEX(t *testing.T, refs ...string) string {
	t.Helper()
	var vulns []any
	for i, ref := range refs {
		vulns = append(vulns, map[string]any{
			"id":       "CVE-2025-200" + string(rune('0'+i)),
			"analysis": map[string]any{"state": "not_affected"},
			"affects":  []any{map[string]any{"ref": ref}},
		})
	}
	raw, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": vulns})
	return writeFile(t, string(raw))
}

func writeFile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vex.json")
	os.WriteFile(p, []byte(text), 0o644)
	return p
}

// The VEX file sets fixed, not affected and affected on the components it points at.
func TestCycloneDXSplitVEX(t *testing.T) {
	sb := load(t, filepath.Join(split, "bom.json"))
	if sb.Serial != serial || sb.BomVersion != 1 || sb.Producer != "meta-cyclonedx" {
		t.Fatalf("serial %q version %d producer %q", sb.Serial, sb.BomVersion, sb.Producer)
	}
	res, err := sbom.LoadVEX(sb, filepath.Join(split, "vex.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Statements != 3 || res.Applied != 3 || res.Skipped != 0 {
		t.Errorf("result %+v", res)
	}
	for _, c := range []struct{ cve, comp, vex string }{
		{"CVE-2025-1001", "openssl", "fixed"},
		{"CVE-2025-1002", "busybox", "not_affected"},
		{"CVE-2025-1003", "linux-yocto", "affected"},
	} {
		if got := sb.Vex(c.cve, c.comp); got != c.vex {
			t.Errorf("%s on %s: %q want %q", c.cve, c.comp, got, c.vex)
		}
	}
	if got := sb.VexNotes("CVE-2025-1002", "busybox"); got != "code_not_present. STATE: cpe-incorrect" {
		t.Errorf("notes %q", got)
	}
}

// A BOM-Link must name this BOM's serial and version and one of its components. A statement
// that misses on any of them is skipped. A file with nothing left is refused.
func TestCycloneDXSplitVEXBadURN(t *testing.T) {
	const other = "00000000-0000-0000-0000-000000000000"
	for name, ref := range map[string]string{
		"wrong serial":   "urn:cdx:" + other + "/1#busybox",
		"wrong ref":      "urn:cdx:" + serial + "/1#nothing",
		"both wrong":     "urn:cdx:" + other + "/1#nothing",
		"wrong version":  "urn:cdx:" + serial + "/2#busybox",
		"plain bom-ref":  "busybox",
		"no ref in link": "urn:cdx:" + serial + "/1#",
	} {
		sb := load(t, filepath.Join(split, "bom.json"))
		_, err := sbom.LoadVEX(sb, writeVEX(t, ref))
		if err == nil || !strings.Contains(err.Error(), "none of its 1 statements point at this SBOM") {
			t.Errorf("%s: got %v", name, err)
		}
		if sb.Vex("CVE-2025-2000", "busybox") != "" {
			t.Errorf("%s: applied", name)
		}
	}

	sb := load(t, filepath.Join(split, "bom.json"))
	res, err := sbom.LoadVEX(sb, writeVEX(t, "urn:cdx:"+serial+"/1#busybox", "urn:cdx:"+other+"/1#openssl"))
	if err != nil || res.Applied != 1 || res.Skipped != 1 {
		t.Errorf("one good and one bad: %+v %v", res, err)
	}
}

// Files that aren't a CycloneDX VEX are refused by name.
func TestCycloneDXSplitVEXFormats(t *testing.T) {
	for name, c := range map[string]struct{ text, want string }{
		"not JSON":           {"not json", "not a CycloneDX JSON VEX document"},
		"SPDX":               {`{"spdxVersion": "SPDX-2.3"}`, "not a CycloneDX JSON VEX document"},
		"OpenVEX":            {`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`, "not a CycloneDX JSON VEX document"},
		"XML":                {`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>`, "CycloneDX XML isn't read"},
		"no vulnerabilities": {`{"bomFormat": "CycloneDX", "specVersion": "1.6"}`, "has no vulnerabilities"},
		"wrong shape":        {`{"bomFormat": "CycloneDX", "vulnerabilities": {}}`, "not valid CycloneDX JSON"},
	} {
		sb := load(t, filepath.Join(split, "bom.json"))
		if _, err := sbom.LoadVEX(sb, writeFile(t, c.text)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v", name, err)
		}
	}

	// The SBOM side must be CycloneDX with a serial number.
	vex := filepath.Join(split, "vex.json")
	if _, err := sbom.LoadVEX(load(t, yocto), vex); err == nil || !strings.Contains(err.Error(), "needs a CycloneDX SBOM") {
		t.Errorf("SPDX SBOM: got %v", err)
	}
	noSerial := filepath.Join(t.TempDir(), "bom.json")
	os.WriteFile(noSerial, []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"bom-ref": "a", "name": "a"}]}`), 0o644)
	if _, err := sbom.LoadVEX(load(t, noSerial), vex); err == nil || !strings.Contains(err.Error(), "no serialNumber") {
		t.Errorf("no serial: got %v", err)
	}
}

// Every statement in a VEX file needs an id and refs and an analysis with a known state.
func TestCycloneDXSplitVEXNeedsFields(t *testing.T) {
	link := `"affects": [{"ref": "urn:cdx:` + serial + `/1#busybox"}]`
	for name, c := range map[string]struct{ vuln, want string }{
		"no id":         {`{"analysis": {"state": "resolved"}, ` + link + `}`, "vulnerability 1 has no id"},
		"no analysis":   {`{"id": "CVE-1", ` + link + `}`, "has no analysis"},
		"no state":      {`{"id": "CVE-1", "analysis": {"detail": "x"}, ` + link + `}`, "analysis with no state"},
		"unknown state": {`{"id": "CVE-1", "analysis": {"state": "fine"}, ` + link + `}`, `unknown analysis state "fine"`},
		"no affects":    {`{"id": "CVE-1", "analysis": {"state": "resolved"}}`, "has no affects"},
		"empty ref":     {`{"id": "CVE-1", "analysis": {"state": "resolved"}, "affects": [{"ref": ""}]}`, "affects entry with no ref"},
	} {
		sb := load(t, filepath.Join(split, "bom.json"))
		text := `{"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": [` + c.vuln + `]}`
		if _, err := sbom.LoadVEX(sb, writeFile(t, text)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
