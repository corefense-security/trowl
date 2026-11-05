package unpack

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
)

func writeTar(t *testing.T, headers ...*tar.Header) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := tar.NewWriter(f)
	defer w.Close()
	for _, h := range headers {
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestTarCantChangeTheHost(t *testing.T) {
	host := t.TempDir()
	os.Chmod(host, 0o700)
	img := writeTar(t,
		&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o777},
		&tar.Header{Name: "d", Typeflag: tar.TypeSymlink, Linkname: host})
	if _, _, err := extractTar(img, filepath.Join(t.TempDir(), "rootfs")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(host); st.Mode().Perm() != 0o700 {
		t.Errorf("host directory is now %o", st.Mode().Perm())
	}
}

func TestTarCantReplaceTheRootfs(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "rootfs")
	img := writeTar(t, &tar.Header{Name: ".", Typeflag: tar.TypeSymlink, Linkname: t.TempDir()})
	skipped, _, err := extractTar(img, dest)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(dest); skipped != 1 || err != nil || !st.IsDir() {
		t.Errorf("skipped %d, rootfs %v, %v", skipped, st, err)
	}
}
