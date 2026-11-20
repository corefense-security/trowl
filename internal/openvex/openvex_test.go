package openvex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadV02(t *testing.T) {
	doc, err := Read(write(t, `{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "author": "a", "timestamp": "2026-01-01T00:00:00Z",
	  "statements": [{
	    "vulnerability": {"name": "GHSA-xxxx", "aliases": ["cve-2024-1"]},
	    "products": [{"@id": "pkg:oci/app", "subcomponents": [{"@id": "pkg:deb/debian/openssl@3.0.15-1"}]}],
	    "status": "not_affected", "justification": "vulnerable_code_not_present",
	    "timestamp": "2026-02-01T00:00:00Z"
	  }]}`))
	if err != nil {
		t.Fatal(err)
	}
	st := doc.Statements[0]
	if got := st.CVEs(); len(got) != 1 || got[0] != "CVE-2024-1" {
		t.Errorf("CVEs %v", got)
	}
	if st.Products[0].Subcomponents[0].ID != "pkg:deb/debian/openssl@3.0.15-1" {
		t.Errorf("products %+v", st.Products)
	}
	if st.Time.Month() != 2 {
		t.Errorf("the statement's own timestamp wins over the document's, got %v", st.Time)
	}
}

// v0.0.x wrote the vulnerability and products as plain strings.
func TestReadOldStringForm(t *testing.T) {
	doc, err := Read(write(t, `{"@context": "https://openvex.dev/ns", "timestamp": "2023-01-01T00:00:00Z",
	  "statements": [{"vulnerability": "CVE-2023-9", "products": ["pkg:generic/busybox@1.36.1"],
	    "subcomponents": ["pkg:generic/libbb"], "status": "fixed"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	st := doc.Statements[0]
	if st.CVEs()[0] != "CVE-2023-9" || st.Products[0].ID != "pkg:generic/busybox@1.36.1" ||
		st.Products[0].Subcomponents[0].ID != "pkg:generic/libbb" {
		t.Errorf("read %+v", st)
	}
}

func TestReadRefusesBadFiles(t *testing.T) {
	for name, body := range map[string]string{
		"not openvex":    `{"bomFormat": "CycloneDX"}`,
		"no statements":  `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`,
		"bad status":     `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": "CVE-1", "products": ["x"], "status": "patched"}]}`,
		"no products":    `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": "CVE-1", "status": "fixed"}]}`,
		"bad reason":     `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": "CVE-1", "products": ["x"], "status": "not_affected", "justification": "nope"}]}`,
		"no vuln":        `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"products": ["x"], "status": "fixed"}]}`,
		"product no ids": `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": "CVE-1", "products": [{}], "status": "fixed"}]}`,
	} {
		if _, err := Read(write(t, body)); err == nil {
			t.Errorf("%s: read without an error", name)
		}
	}
}

func TestParsePURL(t *testing.T) {
	p, ok := ParsePURL("pkg:yocto/core/linux-yocto@6.18.52%2Bgit?arch=x86_64#sub")
	if !ok || p.Type != "yocto" || p.Namespace != "core" || p.Name != "linux-yocto" || p.Version != "6.18.52+git" {
		t.Errorf("got %+v", p)
	}
	q, _ := ParsePURL("pkg:yocto/core/linux-yocto@6.18.52+git")
	if !p.Same(q) {
		t.Error("an encoded and a plain + are the same version")
	}
	noVersion, _ := ParsePURL("pkg:yocto/core/linux-yocto")
	if !noVersion.Same(p) {
		t.Error("a PURL with no version matches every version")
	}
	other, _ := ParsePURL("pkg:generic/linux-yocto@6.18.52+git")
	if other.Same(p) {
		t.Error("another type is another package")
	}
}

func TestParseCPE(t *testing.T) {
	c, ok := ParseCPE(`cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*`)
	if !ok || c != (CPE{"busybox", "busybox", "1.36.1"}) {
		t.Errorf("got %+v", c)
	}
	old, ok := ParseCPE("cpe:/a:busybox:busybox:1.36.1")
	if !ok || !old.Same(c) {
		t.Errorf("2.2 form %+v", old)
	}
	any, _ := ParseCPE("cpe:2.3:a:*:busybox:*:*:*:*:*:*:*:*")
	if !any.Same(c) {
		t.Error("wildcards match")
	}
	if v, _ := ParseCPE(`cpe:2.3:a:x:y\:z:1:*:*:*:*:*:*:*`); v.Product != "y:z" {
		t.Errorf("escaped colon: %+v", v)
	}
}

func TestNameVersion(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:deb/debian/openssl@3.0.15-1":                "openssl 3.0.15-1",
		"cpe:2.3:a:openssl:openssl:3.0.15:*:*:*:*:*:*:*": "openssl 3.0.15",
		"busybox@1.36.1":                                 "busybox 1.36.1",
		"busybox":                                        "busybox ",
	} {
		n, v, ok := NameVersion(in)
		if !ok || n+" "+v != want {
			t.Errorf("%s: got %q %q", in, n, v)
		}
	}
	if _, _, ok := NameVersion("https://example.com/image"); ok {
		t.Error("a URL names no package")
	}
}

func TestNewWritesValidOpenVEX(t *testing.T) {
	d := New([]*Statement{{Vulnerability: Vulnerability{Name: "CVE-2"}, Products: []Product{{ID: "b"}}, Status: "fixed"},
		{Vulnerability: Vulnerability{Name: "CVE-1"}, Products: []Product{{ID: "a"}}, Status: "fixed"}}, timeZero, "0.1.0")
	p := filepath.Join(t.TempDir(), "openvex.json")
	if err := d.Write(p); err != nil {
		t.Fatal(err)
	}
	back, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if back.Statements[0].Vulnerability.Name != "CVE-1" || !strings.HasPrefix(d.ID, "urn:uuid:") || d.Tooling != "trowl/0.1.0" {
		t.Errorf("wrote %+v", d)
	}
}

var timeZero = parseTime("2026-11-19T00:00:00Z")
