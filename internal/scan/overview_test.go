package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/corefense-security/trowl/internal/sbom"
)

func cveRow(id string, score float64, status, shipped string, kernel bool, comp string) *pyjson.Obj {
	return pyjson.O("id", id, "status", status, "shipped", shipped, "kernel", kernel,
		"cvss", pyjson.O("score", score),
		"carriers", []any{pyjson.O("name", comp, "shipped", shipped, "status", status)})
}

func TestTopCVE(t *testing.T) {
	rows := []any{
		cveRow("CVE-3", 9.9, "unpatched", "yes", true, "linux-yocto"),
		cveRow("CVE-2", 9.8, "unpatched", "yes", false, "curl"),
		cveRow("CVE-1", 9.8, "unpatched", "yes", false, "libsoup"),
		cveRow("CVE-4", 10.0, "fixed", "yes", false, "openssl"),
		cveRow("CVE-5", 10.0, "unpatched", "build", false, "gcc"),
		pyjson.O("id", "CVE-6", "status", "unpatched", "shipped", "yes", "kernel", false, "cvss", nil),
	}
	if got, want := topCVE(rows, false), "CVE-3 (CVSS 9.9, linux-yocto)"; got != want {
		t.Errorf("overall = %q, want %q", got, want)
	}
	if got, want := topCVE(rows, true), "CVE-1 (CVSS 9.8, libsoup)"; got != want {
		t.Errorf("userland = %q, want %q", got, want)
	}
	if got := topCVE(nil, false); got != "none" {
		t.Errorf("no rows = %q, want none", got)
	}
}

func TestTopPackages(t *testing.T) {
	got := topPackages([]any{
		pyjson.O("name", "vim", "high", 21),
		pyjson.O("name", "curl", "critical", 13, "high", 34),
		pyjson.O("name", "rsync", "critical", 13, "high", 40),
		pyjson.O("name", "popt", "low", 3),
	}, 2)
	if len(got) != 2 || got[0] != "rsync: 13 critical, 40 high" || got[1] != "curl: 13 critical, 34 high" {
		t.Errorf("got %v", got)
	}
}

func TestCveFactsWithoutSBOM(t *testing.T) {
	row := cveRow("CVE-1", 9.8, "unpatched", "yes", false, "curl")
	row.Set("severity", "critical")
	row.Set("vector", "network")
	row.Set("kev", pyjson.O("date", "2026-01-01"))
	row.Set("epss", pyjson.O("score", 0.5))
	cv := pyjson.O("rows", []any{row}, "unmapped", []any{pyjson.O("name", "x")},
		"sources", pyjson.O("kev", pyjson.O("count", 1), "epss", pyjson.O("date", "d"), "inventory", "rpm"),
		"summary", pyjson.O("severity", pyjson.O("critical", 1), "by_component", []any{pyjson.O("name", "curl", "critical", 1)}))
	sv := pyjson.New()
	cveFacts(sv, cv, false)
	if got := sv.G("SBOM"); got != "Not supplied; package versions came from the image's rpm database" {
		t.Errorf("SBOM = %v", got)
	}
	if sv.G("Critical or high unpatched CVEs with a network attack vector") != 1 ||
		sv.G("Packages not checked for CVEs (no CVE product mapping)") != 1 {
		t.Errorf("facts: %s", pyjson.Default(sv))
	}
	if got := sv.G("Highest-EPSS unpatched CVE"); got != "CVE-1 (EPSS 0.50, curl)" {
		t.Errorf("EPSS = %v", got)
	}
}

func TestCveFactsKernelBackports(t *testing.T) {
	fixed := cveRow("CVE-1", 7.5, "unpatched", "yes", true, "linux")
	fixed.G("carriers").([]any)[0].(*pyjson.Obj).Set("backport", true)
	open := cveRow("CVE-2", 7.5, "unpatched", "yes", true, "linux")
	other := cveRow("CVE-3", 7.5, "fixed", "yes", true, "linux")
	cv := pyjson.O("rows", []any{fixed, open, other}, "sources", pyjson.O("kev", nil, "epss", nil), "summary", pyjson.O())
	sv := pyjson.New()
	cveFacts(sv, cv, true)
	if sv.G("Unpatched kernel CVEs") != 2 || sv.G("Unpatched kernel CVEs with a backport for this kernel's stable series") != 1 {
		t.Errorf("facts: %s", pyjson.Default(sv))
	}
}

func TestKernelFix(t *testing.T) {
	if got, want := kernelFix("PROC_KCORE", "n"), "CONFIG_PROC_KCORE=n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := kernelFix("DEFAULT_MMAP_MIN_ADDR", pyjson.O("min", 65536)), "CONFIG_DEFAULT_MMAP_MIN_ADDR=65536"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCheckKernelVersion(t *testing.T) {
	sb, _ := sbom.FromInventory("test", []sbom.Package{{Name: "linux", Version: "6.18.52",
		Cpes: []string{"cpe:2.3:*:*:linux_kernel:6.18.52:*:*:*:*:*:*:*"}}})
	if err := checkKernelVersion(sb, "6.18.52"); err != nil {
		t.Errorf("same version: %v", err)
	}
	if err := checkKernelVersion(sb, ""); err != nil {
		t.Errorf("no modules: %v", err)
	}
	if err := checkKernelVersion(sb, "5.10.1"); err == nil {
		t.Error("different version: want an error")
	}
}

func TestSecretDirs(t *testing.T) {
	got := secretDirs([]string{"/usr/lib/openssl/ptest/a.pem", "/usr/lib/openssl/ptest/b.pem", "/usr/lib/x/y/z.pem", "/etc/app/c.key"}, 2)
	if got.G("/etc/app") != 1 || got.G("/usr/lib/openssl/ptest") != 2 {
		t.Errorf("kept the wrong directories: %s", pyjson.Default(got))
	}
	if got.G("/usr/lib/x/y") != nil || got.G("Other directories") != 1 {
		t.Errorf("cap not applied: %s", pyjson.Default(got))
	}
}

func TestHardeningFacts(t *testing.T) {
	got := hardeningFacts([]any{
		pyjson.O("kind", "executable", "pie", false, "nx", true, "relro", "partial", "canary", false,
			"fortify", pyjson.O("fortified", 0), "cf_protection", pyjson.O("ibt", false, "shstk", false)),
		pyjson.O("kind", "executable", "pie", true, "nx", true, "relro", "full", "canary", false, "no_symbols", true,
			"fortify", pyjson.O("fortified", 0), "cf_protection", pyjson.O("ibt", true, "shstk", true)),
		pyjson.O("kind", "module", "pie", false),
	})
	for k, want := range map[string]int{"Executables and libraries checked": 2, "Executables without PIE": 1,
		"With only partial RELRO": 1, "Without a stack canary": 1, "Without FORTIFY": 1, "Without CFI": 1} {
		if got.G(k) != want {
			t.Errorf("%s = %v, want %d", k, got.G(k), want)
		}
	}
}

func TestKernelFromPackageDatabaseWithoutModules(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "var/lib/opkg"), 0o755)
	os.WriteFile(filepath.Join(root, "var/lib/opkg/status"), []byte("Package: kernel-image\nVersion: 6.1.20-r0\n"+
		"Source: linux-yocto_6.1.bb\nStatus: install ok installed\n"), 0o644)
	sb, _ := imageInventory(root)
	if sb == nil {
		t.Fatal("no inventory")
	}
	for _, p := range sb.Packages {
		for _, c := range p.Cpes {
			if strings.Contains(c, ":linux_kernel:6.1.20:") {
				return
			}
		}
	}
	t.Error("the kernel was dropped")
}
