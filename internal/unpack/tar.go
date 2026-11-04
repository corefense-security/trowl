package unpack

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/corefense/trowl/internal/py"
)

// extractTar extracts regular files, dirs and symlinks only, and refuses anything escaping dest.
func extractTar(img, dest string) (int, error) {
	skipped := 0
	os.MkdirAll(dest, 0o755)
	root := py.Resolve(dest)
	f, err := os.Open(img)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	type dirAttr struct {
		path string
		mode os.FileMode
		hdr  *tar.Header
	}
	var dirs []dirAttr
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return skipped, err
		}
		name := strings.TrimLeft(h.Name, "/")
		target := py.Resolve(filepath.Join(root, name))
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			skipped++
			continue
		}
		reg := h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA || h.Typeflag == tar.TypeGNUSparse ||
			h.Typeflag == tar.TypeCont
		dir := h.Typeflag == tar.TypeDir
		sym := h.Typeflag == tar.TypeSymlink
		if !(reg || dir || sym) {
			skipped++
			continue
		}
		out := filepath.Join(root, filepath.FromSlash(name))
		mode := os.FileMode(h.Mode & 0o7777)
		switch {
		case dir:
			os.MkdirAll(out, 0o755)
			dirs = append(dirs, dirAttr{out, mode, h})
		case sym:
			os.MkdirAll(filepath.Dir(out), 0o755)
			os.Remove(out)
			os.Symlink(h.Linkname, out)
		case reg:
			os.MkdirAll(filepath.Dir(out), 0o755)
			os.Remove(out)
			w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				continue
			}
			io.Copy(w, tr)
			w.Close()
			os.Chmod(out, mode)
			os.Chtimes(out, h.ModTime, h.ModTime)
		}
	}
	// Like tarfile.extract, directory attributes are applied as each member is extracted;
	// applying them last keeps a read-only directory from blocking its own contents.
	for i := len(dirs) - 1; i >= 0; i-- {
		os.Chmod(dirs[i].path, dirs[i].mode)
		os.Chtimes(dirs[i].path, dirs[i].hdr.ModTime, dirs[i].hdr.ModTime)
	}
	return skipped, nil
}
