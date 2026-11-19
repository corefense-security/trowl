package unpack

import (
	"bufio"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/corefense-security/trowl/internal/py"
)

// Yocto writes its cpio images and initramfs in the newc format (cpio -o -H newc). Both the plain
// "070701" and the CRC "070702" magic are read.
const (
	cpioNewc    = "070701"
	cpioNewcCRC = "070702"
	cpioTrailer = "TRAILER!!!"
	cpioHeader  = 110
	cpioMaxName = 4096
)

func isCpio(path string) bool {
	h := string(magic(path, 6))
	return h == cpioNewc || h == cpioNewcCRC
}

type cpioEntry struct {
	ino, mode, uid, gid, nlink, devMajor, devMinor int
	mtime, size                                    int64
	name                                           string
}

// readCpioHeader reads one header and its name and skips the padding after the name.
func readCpioHeader(r *bufio.Reader) (*cpioEntry, error) {
	var hdr [cpioHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, errorf("cpio archive ends early")
	}
	m := string(hdr[:6])
	if m != cpioNewc && m != cpioNewcCRC {
		return nil, errorf("cpio archive isn't in the newc format")
	}
	field := func(i int) (int64, error) {
		return strconv.ParseInt(string(hdr[6+8*i:14+8*i]), 16, 64)
	}
	var v [13]int64
	for i := range v {
		n, err := field(i)
		if err != nil {
			return nil, errorf("cpio archive has a bad header")
		}
		v[i] = n
	}
	nameSize := v[11]
	if nameSize < 1 || nameSize > cpioMaxName {
		return nil, errorf("cpio archive has a bad file name length")
	}
	name := make([]byte, nameSize)
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, errorf("cpio archive ends early")
	}
	if _, err := r.Discard(int(pad4(cpioHeader + nameSize))); err != nil {
		return nil, errorf("cpio archive ends early")
	}
	return &cpioEntry{ino: int(v[0]), mode: int(v[1]), uid: int(v[2]), gid: int(v[3]), nlink: int(v[4]),
		mtime: v[5], size: v[6], devMajor: int(v[7]), devMinor: int(v[8]),
		name: strings.TrimRight(string(name), "\x00")}, nil
}

func pad4(n int64) int64 { return (4 - n%4) % 4 }

// inside reports whether the resolved path target is root or under it.
func inside(root, target string) bool {
	return target == root || strings.HasPrefix(target, root+string(filepath.Separator))
}

// extractCpio extracts regular files, dirs and symlinks only. Like extractTar it refuses anything
// that escapes dest or replaces dest itself. In newc hard links share an inode and only the last
// one carries the data. The earlier names are filled in when it arrives.
func extractCpio(img, dest string, p Progress) (int, map[string]Perm, error) {
	skipped := 0
	perms := map[string]Perm{}
	os.MkdirAll(dest, 0o755)
	root := py.Resolve(dest)
	f, err := os.Open(img)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	p.Stage("extracting cpio", fileSize(img))
	r := bufio.NewReaderSize(counting{f, p}, 1<<20)
	type dirAttr struct {
		path  string
		mode  os.FileMode
		mtime time.Time
	}
	var dirs []dirAttr
	type inode struct{ ino, major, minor int }
	waiting := map[inode][]string{} // hard link names still without data
	for {
		e, err := readCpioHeader(r)
		if err != nil {
			return skipped, nil, err
		}
		if e.name == cpioTrailer {
			break
		}
		if e.size < 0 {
			return skipped, nil, errorf("cpio archive has a bad file size")
		}
		data := io.LimitReader(r, e.size)
		skip := func() error {
			if _, err := io.Copy(io.Discard, data); err != nil {
				return errorf("cpio archive ends early")
			}
			_, err := r.Discard(int(pad4(e.size)))
			return err
		}
		name := strings.TrimPrefix(strings.TrimLeft(e.name, "/"), "./")
		target := py.Resolve(filepath.Join(root, name))
		out := filepath.Join(root, filepath.FromSlash(name))
		kind := e.mode & 0o170000
		reg, dir, sym := kind == 0o100000, kind == 0o040000, kind == 0o120000
		if !inside(root, target) || !(reg || dir || sym) || (out == root && !dir) || name == "" && !dir {
			skipped++
			if err := skip(); err != nil {
				return skipped, nil, err
			}
			continue
		}
		mode := os.FileMode(e.mode & 0o7777)
		mtime := time.Unix(e.mtime, 0)
		switch {
		case dir:
			os.MkdirAll(out, 0o755)
			dirs = append(dirs, dirAttr{out, mode, mtime})
		case sym:
			if e.size > cpioMaxName {
				return skipped, nil, errorf("cpio archive has a bad link target length")
			}
			link, err := io.ReadAll(data)
			if err != nil || int64(len(link)) != e.size {
				return skipped, nil, errorf("cpio archive ends early")
			}
			os.MkdirAll(filepath.Dir(out), 0o755)
			os.Remove(out)
			os.Symlink(string(link), out)
		case reg:
			key := inode{e.ino, e.devMajor, e.devMinor}
			imagePath := path.Clean("/" + name)
			perms[imagePath] = Perm{e.mode & 0o7777, e.uid, e.gid}
			if e.size == 0 && e.nlink > 1 {
				waiting[key] = append(waiting[key], out)
				break
			}
			os.MkdirAll(filepath.Dir(out), 0o755)
			os.Remove(out)
			w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				break
			}
			_, err = io.Copy(w, data)
			w.Close()
			if err != nil {
				return skipped, nil, errorf("cpio archive ends early")
			}
			os.Chmod(out, mode)
			os.Chtimes(out, mtime, mtime)
			for _, other := range waiting[key] {
				// A later member may have turned a parent directory into a link.
				if !inside(root, py.Resolve(other)) {
					skipped++
					continue
				}
				os.MkdirAll(filepath.Dir(other), 0o755)
				os.Remove(other)
				os.Link(out, other)
			}
			delete(waiting, key)
		}
		if err := skip(); err != nil {
			return skipped, nil, err
		}
	}
	// Like GNU cpio, hard links that never got their data become empty files.
	for _, names := range waiting {
		for _, n := range names {
			if !inside(root, py.Resolve(n)) {
				skipped++
				continue
			}
			os.MkdirAll(filepath.Dir(n), 0o755)
			if w, err := os.OpenFile(n, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
				w.Close()
			}
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if st, err := os.Lstat(dirs[i].path); err != nil || !st.IsDir() {
			continue
		}
		os.Chmod(dirs[i].path, dirs[i].mode)
		os.Chtimes(dirs[i].path, dirs[i].mtime, dirs[i].mtime)
	}
	return skipped, perms, nil
}
