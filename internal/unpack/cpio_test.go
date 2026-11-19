package unpack

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// cpioMember is one newc entry for writeCpio.
type cpioMember struct {
	name        string
	mode, nlink int
	ino         int
	data        string
}

func writeCpio(t *testing.T, members ...cpioMember) string {
	t.Helper()
	var b bytes.Buffer
	add := func(m cpioMember) {
		nlink := m.nlink
		if nlink == 0 {
			nlink = 1
		}
		fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			m.ino, m.mode, 0, 0, nlink, 0, len(m.data), 0, 0, 0, 0, len(m.name)+1, 0)
		b.WriteString(m.name + "\x00")
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
		b.WriteString(m.data)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	for i, m := range members {
		if m.ino == 0 {
			m.ino = i + 1
		}
		add(m)
	}
	add(cpioMember{name: cpioTrailer})
	p := filepath.Join(t.TempDir(), "image.cpio")
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCpioExtractsFilesDirsAndLinks(t *testing.T) {
	img := writeCpio(t,
		cpioMember{name: "etc", mode: 0o040755},
		cpioMember{name: "etc/passwd", mode: 0o100644, data: "root:x:0:0\n"},
		cpioMember{name: "bin/su", mode: 0o104755, data: "elf"},
		cpioMember{name: "sbin", mode: 0o120777, data: "bin"},
		cpioMember{name: "dev/console", mode: 0o020600})
	if !isCpio(img) {
		t.Fatal("not detected as cpio")
	}
	dest := filepath.Join(t.TempDir(), "rootfs")
	skipped, perms, err := extractCpio(img, dest, noProgress{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "etc/passwd")); string(got) != "root:x:0:0\n" {
		t.Errorf("passwd is %q", got)
	}
	if link, _ := os.Readlink(filepath.Join(dest, "sbin")); link != "bin" {
		t.Errorf("sbin links to %q", link)
	}
	if perms["/bin/su"].Mode != 0o4755 {
		t.Errorf("su mode %o", perms["/bin/su"].Mode)
	}
	if skipped != 1 {
		t.Errorf("skipped %d, want the device node", skipped)
	}
}

// newc stores a hard link's data with its last name only.
func TestCpioHardLinks(t *testing.T) {
	img := writeCpio(t,
		cpioMember{name: "bin/a", mode: 0o100755, nlink: 2, ino: 7},
		cpioMember{name: "bin/b", mode: 0o100755, nlink: 2, ino: 7, data: "busybox"})
	dest := filepath.Join(t.TempDir(), "rootfs")
	if _, _, err := extractCpio(img, dest, noProgress{}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"bin/a", "bin/b"} {
		if got, _ := os.ReadFile(filepath.Join(dest, n)); string(got) != "busybox" {
			t.Errorf("%s is %q", n, got)
		}
	}
}

func TestCpioCantWriteOutsideTheRootfs(t *testing.T) {
	host := t.TempDir()
	img := writeCpio(t,
		cpioMember{name: "../escape", mode: 0o100644, data: "x"},
		cpioMember{name: "d", mode: 0o120777, data: host},
		cpioMember{name: "d/planted", mode: 0o100644, data: "x"})
	skipped, _, err := extractCpio(img, filepath.Join(t.TempDir(), "rootfs"), noProgress{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(host, "planted")); err == nil {
		t.Error("wrote through a link to the host")
	}
	if skipped != 2 {
		t.Errorf("skipped %d, want 2", skipped)
	}
}

func TestCpioTruncatedIsAnError(t *testing.T) {
	img := writeCpio(t, cpioMember{name: "etc/passwd", mode: 0o100644, data: "root:x:0:0\n"})
	raw, _ := os.ReadFile(img)
	os.WriteFile(img, raw[:130], 0o644)
	if _, _, err := extractCpio(img, filepath.Join(t.TempDir(), "rootfs"), noProgress{}); err == nil {
		t.Error("a cut-short archive extracted without an error")
	}
}

// Unpack reads a GNU cpio archive compressed with legacy lz4 like Yocto's cpio.lz4.
func TestUnpackCpioLz4(t *testing.T) {
	for _, tool := range []string{"cpio", "lz4"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " isn't installed")
		}
	}
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "etc"), 0o755)
	os.MkdirAll(filepath.Join(src, "usr/bin"), 0o755)
	os.WriteFile(filepath.Join(src, "etc/os-release"), []byte("ID=poky\n"), 0o644)
	img := filepath.Join(t.TempDir(), "image.cpio.lz4")
	cmd := exec.Command("sh", "-c", "find . | cpio -o -H newc --quiet | lz4 -l -9 -q - "+img)
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	u, err := Unpack(img, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.SourceFormat != "lz4+cpio" {
		t.Errorf("format %q", u.SourceFormat)
	}
	if got, _ := os.ReadFile(filepath.Join(u.Rootfs, "etc/os-release")); string(got) != "ID=poky\n" {
		t.Errorf("os-release is %q", got)
	}
}
