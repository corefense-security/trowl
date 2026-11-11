package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Every fingerprint loads, and gives each of its examples' versions and none of its rejects.
func TestFingerprintExamples(t *testing.T) {
	fingerprints, err := loadFingerprints()
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprints) == 0 {
		t.Fatal("no fingerprints embedded")
	}
	for _, c := range fingerprints {
		for _, ex := range c.Examples {
			content := func() []byte { return []byte(ex.Contains) }
			if got := c.versionOf(ex.File, content); got != ex.Version {
				t.Errorf("%s: example %s %q: version %q, want %q", c.file, ex.File, ex.Contains, got, ex.Version)
			}
		}
		for _, ex := range c.Rejects {
			content := func() []byte { return []byte(ex.Contains) }
			if got := c.versionOf(ex.File, content); got != "" {
				t.Errorf("%s: reject %s %q: matched version %q", c.file, ex.File, ex.Contains, got)
			}
		}
	}
}

func TestFingerprintChecks(t *testing.T) {
	ok := func() fingerprint {
		return fingerprint{Package: "x", CPEs: []string{"cpe:2.3:a:v:x"}, Examples: []example{{File: "x"}},
			Evidence: []evidence{{Files: []string{"x"}, Pattern: `x (?P<version>\d+)`}}}
	}
	for name, edit := range map[string]func(*fingerprint){
		"no package":       func(c *fingerprint) { c.Package = "" },
		"cpe with version": func(c *fingerprint) { c.CPEs = []string{"cpe:2.3:a:v:x:1.0"} },
		"no version group": func(c *fingerprint) { c.Evidence[0].Pattern = `x \d+` },
		"partial parts":    func(c *fingerprint) { c.Evidence[0].Pattern = `(?P<major>\d)(?P<minor>\d)` },
		"both patterns":    func(c *fingerprint) { c.Evidence[0].NamePattern = `(?P<version>\d+)` },
		"no files":         func(c *fingerprint) { c.Evidence[0].Files = nil },
		"bad glob":         func(c *fingerprint) { c.Evidence[0].Files = []string{"["} },
		"no examples":      func(c *fingerprint) { c.Examples = nil },
	} {
		c := ok()
		edit(&c)
		if c.prepare() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := ok()
	if err := c.prepare(); err != nil {
		t.Errorf("valid fingerprint rejected: %v", err)
	}
}

func TestFingerprints(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	elf := "\x7fELF\x02\x01\x01"
	write("usr/sbin/sshd", elf+"\x00OpenSSH_3.*\x00command-line\x00OpenSSH_10.3p1\x00%s")
	write("usr/bin/ssh.openssh", elf+"\x00OpenSSH_10.3p1\x00")
	write("usr/lib/liblzma.so.5.8.2", elf)
	write("usr/lib/libz.so.1.3.2", "not an ELF file - deflate 1.3.2 Copyright") // skipped: not ELF
	write("opt/old/lib/liblzma.so.5.4.1", elf)                                  // a second version
	if err := os.Symlink("ssh.openssh", filepath.Join(root, "usr/bin/ssh")); err != nil {
		t.Fatal(err)
	}

	got, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Found{
		{Name: "openssh", Version: "10.3p1", CPEs: []string{"cpe:2.3:a:openbsd:openssh:10.3p1:*:*:*:*:*:*:*"},
			Files: []string{"/usr/bin/ssh.openssh", "/usr/sbin/sshd"}},
		{Name: "xz", Version: "5.4.1", CPEs: []string{"cpe:2.3:a:tukaani:xz:5.4.1:*:*:*:*:*:*:*"},
			Files: []string{"/opt/old/lib/liblzma.so.5.4.1"}},
		{Name: "xz", Version: "5.8.2", CPEs: []string{"cpe:2.3:a:tukaani:xz:5.8.2:*:*:*:*:*:*:*"},
			Files: []string{"/usr/lib/liblzma.so.5.8.2"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Fingerprint:\n got  %+v\n want %+v", got, want)
	}
}

// TestFingerprintRootfs runs the fingerprints over a real unpacked rootfs, the Yocto core-image-minimal
// the entries were written from. Run it with
// TROWL_FINGERPRINT_ROOTFS=/path/to/rootfs go test ./internal/inventory/
func TestFingerprintRootfs(t *testing.T) {
	root := os.Getenv("TROWL_FINGERPRINT_ROOTFS")
	if root == "" {
		t.Skip("set TROWL_FINGERPRINT_ROOTFS to an unpacked core-image-minimal rootfs")
	}
	got, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]string{}
	for _, f := range got {
		if v, ok := versions[f.Name]; ok {
			t.Errorf("%s: two versions, %s and %s (%v)", f.Name, v, f.Version, f.Files)
		}
		versions[f.Name] = f.Version
	}
	want := map[string]string{"acl": "2.3.2", "attr": "2.5.2", "busybox": "1.37.0", "eudev": "3.2.14", "glibc": "2.43", "kmod": "34.2",
		"libxcrypt": "4.5.2", "openssh": "10.3p1", "openssl": "3.5.9", "shadow": "4.19.4", "sysvinit": "3.14",
		"tar": "1.35", "util-linux": "2.41.6", "xz": "5.8.2", "zlib": "1.3.2"}
	if !reflect.DeepEqual(versions, want) {
		t.Errorf("versions:\n got  %v\n want %v", versions, want)
	}
}
