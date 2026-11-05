package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/corefense-security/trowl/internal/pyjson"
)

func TestLoadRefusesWhatIsNotAnSBOM(t *testing.T) {
	for name, text := range map[string]string{
		"plain text": "not json",
		"truncated":  `{"@graph": [{"type": "software_Pack`,
		"SPDX 2.3":   `{"spdxVersion": "SPDX-2.3", "packages": []}`,
	} {
		p := filepath.Join(t.TempDir(), "sbom.json")
		os.WriteFile(p, []byte(text), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestKernelOnABootPartitionIsNotAbsent(t *testing.T) {
	sb := &Sbom{Packages: map[string]*Package{"k": {ID: "k", Role: "package", Files: []File{{Name: "/boot/bzImage"}}}},
		PackageOrder: []string{"k"}, Generates: newIDList()}
	for other, want := range map[bool]string{false: "absent", true: "no-files"} {
		if got := Compare(sb, t.TempDir(), other).Status.Of("k"); got != want {
			t.Errorf("other partitions %v: %s, want %s", other, got, want)
		}
	}
}

func TestUnknownStaysInPlay(t *testing.T) {
	rows := []*pyjson.Obj{
		pyjson.O("status", "unpatched", "shipped", "unknown", "severity", "high", "kev", nil, "carriers", []any{}),
		pyjson.O("status", "unpatched", "shipped", "no", "severity", "high", "kev", nil, "carriers", []any{}),
	}
	s := Summary(rows)
	if s.G("unpatched_shipped") != 1 || s.G("unpatched_not_shipped") != 1 {
		t.Errorf("shipped %v, not shipped %v", s.G("unpatched_shipped"), s.G("unpatched_not_shipped"))
	}
}

func TestNameOnlyIsForVersionMatches(t *testing.T) {
	sb, _ := FromInventory("opkg", []Package{{Name: "phone", Version: "1.0"}})
	sb.vex[pair{"CVE-1", "inventory/phone"}] = "affected" // as the SBOM would list it
	sb.AddMatch("inventory/phone", "CVE-1", nil)
	sb.AddMatch("inventory/phone", "CVE-2", nil)
	sb.MarkNameOnly("inventory/phone", "CVE-1")
	sb.MarkNameOnly("inventory/phone", "CVE-2")
	if sb.NameOnly("CVE-1", "inventory/phone") || !sb.NameOnly("CVE-2", "inventory/phone") {
		t.Errorf("listed %v, matched %v", sb.NameOnly("CVE-1", "inventory/phone"), sb.NameOnly("CVE-2", "inventory/phone"))
	}
}
