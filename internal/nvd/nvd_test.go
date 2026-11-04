package nvd

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.3.2", "1.3.2", 0},
		{"1.3.2", "1.3.10", -1},
		{"10.3p1", "10.3", 1},
		{"10.3p1", "10.6", -1},
		{"10.3p1", "10.3p2", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0.1", "1.0rc1", 1},
		{"6.18.52", "6.18.52", 0},
		{"6.18.52", "6.18.6", 1},
		{"2.41.6", "2.42", -1},
		{"1.2.3+git0+abcdef", "1.2.3", 0},
		{"1:2.0", "2.0", 0},
		{"3.51.3", "3.51.03", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestInRange(t *testing.T) {
	m := cpeMatch{Vulnerable: true, VersionEndExcluding: "10.6"}
	if !inRange("10.3p1", "*", "*", m) {
		t.Error("10.3p1 should be below 10.6")
	}
	if inRange("10.6", "*", "*", m) {
		t.Error("10.6 is the fix")
	}
	if !inRange("10.3p1", "10.3", "p1", cpeMatch{}) {
		t.Error("exact version with update")
	}
	if inRange("10.3p1", "10.3", "p2", cpeMatch{}) {
		t.Error("different update")
	}
	if !inRange("1.2", "*", "*", cpeMatch{}) {
		t.Error("* without a range covers every version")
	}
	if inRange("1.2", "-", "*", cpeMatch{}) {
		t.Error("- is not applicable")
	}
}

func TestKernelAffected(t *testing.T) {
	// Shape of a kernel CNA block: introduced in 4.7, fixed in several stable series.
	b := affectedData{DefaultStatus: "affected", Versions: []cnaVersion{
		{Version: "4.7", Status: "affected"},
		{Version: "0", LessThan: "4.7", VersionType: "semver", Status: "unaffected"},
		{Version: "6.6.157", LessThanOrEqual: "6.6.*", VersionType: "semver", Status: "unaffected"},
		{Version: "6.18.52", LessThanOrEqual: "6.18.*", VersionType: "semver", Status: "unaffected"},
		{Version: "7.3", LessThanOrEqual: "*", VersionType: "original_commit_for_fix", Status: "unaffected"},
	}}
	cases := map[string]bool{
		"4.6":     false, // before it was introduced
		"6.6.100": true,  // before the 6.6 fix
		"6.6.157": false, // the 6.6 fix
		"6.18.51": true,
		"6.18.52": false,
		"6.12.40": true, // no fix in the 6.12 series
		"7.3":     false,
		"7.4.1":   false,
	}
	for v, want := range cases {
		if got := cnaAffected(v, b, true); got != want {
			t.Errorf("cnaAffected(%s) = %v, want %v", v, got, want)
		}
	}
}

func TestSplitCPE(t *testing.T) {
	p := splitCPE(`cpe:2.3:a:openbsd:openssh:10.3:p1:*:*:*:*:*:*`)
	if len(p) != 13 || p[3] != "openbsd" || p[4] != "openssh" || p[5] != "10.3" || p[6] != "p1" {
		t.Errorf("splitCPE: %q", p)
	}
	p = splitCPE(`cpe:2.3:a:foo:bar\:baz:1.0:*:*:*:*:*:*:*`)
	if p[4] != "bar:baz" {
		t.Errorf("escaped colon: %q", p[4])
	}
}

func TestKernelFixedInOlderSeries(t *testing.T) {
	// CVE-2021-47645: fixes listed only up to 5.17.2, no mainline entry.
	b := affectedData{DefaultStatus: "affected", Versions: []cnaVersion{
		{Version: "5.10", Status: "affected"},
		{Version: "0", LessThan: "5.10", VersionType: "semver", Status: "unaffected"},
		{Version: "5.15.33", LessThanOrEqual: "5.15.*", VersionType: "semver", Status: "unaffected"},
		{Version: "5.17.2", LessThanOrEqual: "5.17.*", VersionType: "semver", Status: "unaffected"},
	}}
	if cnaAffected("6.18.52", b, true) {
		t.Error("6.18.52 is newer than every fixed series")
	}
	if !cnaAffected("5.15.20", b, true) {
		t.Error("5.15.20 predates the 5.15 fix")
	}
}

func TestCNAUserland(t *testing.T) {
	cases := []struct {
		v    string
		b    affectedData
		want bool
	}{
		{"10.3p1", affectedData{DefaultStatus: "unknown", Versions: []cnaVersion{{Version: "0", LessThanOrEqual: "10.6", VersionType: "custom", Status: "affected"}}}, true},
		{"2.3.2", affectedData{DefaultStatus: "affected", Versions: []cnaVersion{{Version: "0", LessThan: "2.4.0", VersionType: "semver", Status: "affected"}}}, true},
		{"2.4.0", affectedData{DefaultStatus: "unaffected", Versions: []cnaVersion{{Version: "0", LessThan: "2.4.0", VersionType: "semver", Status: "affected"}}}, false},
		{"1.3.2", affectedData{DefaultStatus: "unaffected", Versions: []cnaVersion{{Version: "1.2.11", LessThanOrEqual: "1.3.2", VersionType: "custom", Status: "affected"}}}, true},
		{"1.37.0", affectedData{DefaultStatus: "unknown", Versions: []cnaVersion{{Version: "1.37.0", Status: "affected"}}}, true},
		{"1.36.1", affectedData{DefaultStatus: "unknown", Versions: []cnaVersion{{Version: "1.37.0", Status: "affected"}}}, false},
		{"2.41.6", affectedData{Versions: []cnaVersion{{Version: ">= 2.17, <= 2.41.6", Status: "affected"}}}, true},
		{"2.41.7", affectedData{Versions: []cnaVersion{{Version: ">= 2.17, <= 2.41.6", Status: "affected"}}}, false},
	}
	for _, c := range cases {
		if got := cnaAffected(c.v, c.b, false); got != c.want {
			t.Errorf("cnaAffected(%s, %+v) = %v, want %v", c.v, c.b.Versions, got, c.want)
		}
	}
}

func TestKernelTwoBlocks(t *testing.T) {
	// CVE-2026-93189: per-branch affected ranges in one block, fixed versions in the other.
	branches := affectedData{DefaultStatus: "unaffected", Versions: []cnaVersion{
		{Version: "0", LessThan: "6.18.52", VersionType: "semver", Status: "affected"},
		{Version: "0", LessThan: "7.2.6", VersionType: "semver", Status: "affected"},
	}}
	fixes := affectedData{DefaultStatus: "affected", Versions: []cnaVersion{
		{Version: "6.18.52", LessThanOrEqual: "6.18.*", VersionType: "semver", Status: "unaffected"},
		{Version: "7.2.6", LessThanOrEqual: "7.2.*", VersionType: "semver", Status: "unaffected"},
		{Version: "7.3", LessThanOrEqual: "*", VersionType: "original_commit_for_fix", Status: "unaffected"},
	}}
	if kernelAffected("6.18.52", []affectedData{branches, fixes}) {
		t.Error("6.18.52 carries the 6.18 fix")
	}
	if !kernelAffected("6.18.40", []affectedData{branches, fixes}) {
		t.Error("6.18.40 predates the 6.18 fix")
	}
}

func TestVendorAgrees(t *testing.T) {
	for _, c := range []struct {
		cpe, cna string
		want     bool
	}{{"*", "Ruby", true}, {"gnu", "ruby", false}, {"zlib", "zlib", true}, {"gnu", "GNU", true},
		{"openbsd", "OpenBSD", true}, {"acl_project", "acl project", true}} {
		if got := vendorAgrees(c.cpe, c.cna); got != c.want {
			t.Errorf("vendorAgrees(%q, %q) = %v", c.cpe, c.cna, got)
		}
	}
}

func TestKernelBackportedIntoBranch(t *testing.T) {
	// CVE-2026-72315: introduced in 7.0 and backported into 6.18.20, fixed in 6.18.54. The fixes
	// block's "0 <= v < 7.0 unaffected" is about mainline and must not clear 6.18.52.
	branches := affectedData{DefaultStatus: "unaffected", Versions: []cnaVersion{
		{Version: "6.18.20", LessThan: "6.18.54", VersionType: "semver", Status: "affected"},
	}}
	fixes := affectedData{DefaultStatus: "affected", Versions: []cnaVersion{
		{Version: "7.0", Status: "affected"},
		{Version: "0", LessThan: "7.0", VersionType: "semver", Status: "unaffected"},
		{Version: "6.18.54", LessThanOrEqual: "6.18.*", VersionType: "semver", Status: "unaffected"},
		{Version: "7.2", LessThanOrEqual: "*", VersionType: "original_commit_for_fix", Status: "unaffected"},
	}}
	bs := []affectedData{branches, fixes}
	for v, want := range map[string]bool{"6.18.52": true, "6.18.10": false, "6.18.54": false, "6.12.40": false, "7.1": true, "7.2.1": false} {
		if got := kernelAffected(v, bs); got != want {
			t.Errorf("kernelAffected(%s) = %v, want %v", v, got, want)
		}
	}
}
