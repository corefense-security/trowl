// Package sbom tests loading SBOMs with sbom.Load, as a scan does.
package sbom

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/corefense-security/trowl/internal/sbom"
)

// yocto is a small create-spdx-2.2 set. The image has busybox and busybox-syslog, both built by
// the busybox recipe, and busybox-syslog needs busybox at runtime.
const yocto = "testdata/spdx22-yocto"

const ns = "http://spdx.org/spdxdocs/"

var (
	recipe = ns + "recipe-busybox-4444#SPDXRef-Recipe-busybox"
	pkg    = ns + "busybox-2222#SPDXRef-Package-busybox"
	syslog = ns + "busybox-syslog-3333#SPDXRef-Package-busybox-syslog"
)

func load(t *testing.T, path string) *sbom.Sbom {
	t.Helper()
	sb, err := sbom.Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	return sb
}

// The documents are joined into one SBOM with roles, CPEs, fixed CVEs, files and links.
func TestSpdx22YoctoSet(t *testing.T) {
	sb := load(t, yocto)
	if sb.Name != "core-image-minimal-qemux86-64.rootfs" {
		t.Errorf("name %q", sb.Name)
	}
	if sb.Format != "SPDX 2.2" || sb.Documents != 5 {
		t.Errorf("format %q from %d documents, want SPDX 2.2 from 5", sb.Format, sb.Documents)
	}
	roles := map[string]int{}
	for _, id := range sb.PackageOrder {
		roles[sb.Packages[id].Role]++
	}
	if want := map[string]int{"rootfs": 1, "package": 2, "recipe": 1, "source": 1}; !reflect.DeepEqual(roles, want) {
		t.Errorf("roles %v, want %v", roles, want)
	}

	r := sb.Packages[recipe]
	if r == nil || r.Version != "1.36.1" || !reflect.DeepEqual(r.Cpes, []string{"cpe:2.3:*:*:busybox:1.36.1:*:*:*:*:*:*:*"}) {
		t.Fatalf("recipe %+v", r)
	}
	if got := sb.Vulns.M[recipe]; !reflect.DeepEqual(got, []string{"CVE-2022-48174", "CVE-2023-42363"}) {
		t.Errorf("recipe CVEs %v", got)
	}
	if v := sb.Vex("CVE-2023-42363", recipe); v != "fixed" {
		t.Errorf("CVE-2023-42363 is %q, want fixed", v)
	}

	p := sb.Packages[pkg]
	if p == nil || len(p.Files) != 1 || p.Files[0].Name != "bin/busybox" || p.Files[0].Sha256 == nil ||
		!strings.HasPrefix(*p.Files[0].Sha256, "e496cf82") {
		t.Fatalf("busybox package %+v", p)
	}
	if got := sb.Generates.M[recipe]; !reflect.DeepEqual(got, []string{pkg, syslog}) {
		t.Errorf("recipe generates %v", got)
	}
	if got := sb.RuntimeDeps.M[syslog]; !reflect.DeepEqual(got, []string{pkg}) {
		t.Errorf("busybox-syslog depends on %v", got)
	}
}

// Yocto ships the set as IMAGE.spdx.tar.zst. A tar, compressed or not, loads the same as the
// directory.
func TestSpdx22Archives(t *testing.T) {
	want := load(t, yocto)
	dir := t.TempDir()
	plain := filepath.Join(dir, "image.spdx.tar")
	writeTar(t, plain, yocto)
	paths := []string{plain}
	if _, err := exec.LookPath("zstd"); err == nil {
		zst := plain + ".zst"
		if out, err := exec.Command("zstd", "-q", plain, "-o", zst).CombinedOutput(); err != nil {
			t.Fatalf("zstd: %v %s", err, out)
		}
		// Yocto writes it with pzstd, which puts a skippable frame first.
		raw, _ := os.ReadFile(zst)
		pz := plain + ".pzstd.zst"
		os.WriteFile(pz, append([]byte{0x50, 0x2a, 0x4d, 0x18, 4, 0, 0, 0, 0, 0, 0, 0}, raw...), 0o644)
		paths = append(paths, zst, pz)
	} else {
		t.Log("zstd not installed: .tar.zst not tested")
	}
	for _, p := range paths {
		got := load(t, p)
		if !reflect.DeepEqual(got.PackageOrder, want.PackageOrder) || !reflect.DeepEqual(got.Generates, want.Generates) ||
			!reflect.DeepEqual(got.Vulns, want.Vulns) {
			t.Errorf("%s loads differently from the directory", filepath.Base(p))
		}
	}
}

// spdxVersion decides the format. SPDX-2.2 loads and other 2.x versions are refused by name.
// A Yocto image document on its own only points to the others, so the error says what to pass.
func TestSpdx22Version(t *testing.T) {
	image := filepath.Join(yocto, "core-image-minimal-qemux86-64.rootfs.spdx.json")
	if _, err := sbom.Load(image); err == nil || !strings.Contains(err.Error(), "IMAGE.spdx.tar.zst") {
		t.Errorf("lone image document: %v", err)
	}

	mixed := t.TempDir()
	for _, name := range []string{"busybox.spdx.json", "recipe-busybox.spdx.json"} {
		raw, _ := os.ReadFile(filepath.Join(yocto, name))
		if name == "recipe-busybox.spdx.json" {
			raw = []byte(strings.Replace(string(raw), "SPDX-2.2", "SPDX-2.3", 1))
		}
		os.WriteFile(filepath.Join(mixed, name), raw, 0o644)
	}
	if _, err := sbom.Load(mixed); err == nil || !strings.Contains(err.Error(), "SPDX-2.3 isn't supported") {
		t.Errorf("set with an SPDX 2.3 document: %v", err)
	}

	// A single document, as other tools write it.
	single := filepath.Join(t.TempDir(), "app.spdx.json")
	os.WriteFile(single, []byte(`{"spdxVersion": "SPDX-2.2", "name": "app", "documentNamespace": "urn:app",
		"packages": [{"SPDXID": "SPDXRef-zlib", "name": "zlib", "versionInfo": "1.3.1"}]}`), 0o644)
	sb := load(t, single)
	if p := sb.Packages["urn:app#SPDXRef-zlib"]; p == nil || p.Role != "package" || p.Version != "1.3.1" {
		t.Errorf("single document: %+v", sb.Packages)
	}
}

func writeTar(t *testing.T, dst, dir string) {
	t.Helper()
	f, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		tw.WriteHeader(&tar.Header{Name: e.Name(), Mode: 0o644, Size: int64(len(raw)), Typeflag: tar.TypeReg})
		tw.Write(raw)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}
