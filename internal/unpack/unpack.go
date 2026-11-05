// Package unpack turns an image (directory, tarball, ext2/3/4, squashfs, or partitioned disk)
// into a directory tree.
//
// Nothing is mounted and nothing needs root: filesystems are extracted with debugfs/unsquashfs,
// partitioned images are split by reading the MBR/GPT ourselves. Compressed wrappers
// (.zst/.xz/.gz/.bz2) are detected by magic, not by file extension.
package unpack

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/corefense-security/trowl/internal/py"
	"github.com/ulikunitz/xz"
)

const sector = 512

type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errorf(format string, a ...any) error { return &Error{fmt.Sprintf(format, a...)} }

type Unpacked struct {
	Rootfs       string
	SourceFormat string
	Notes        []string
	Perms        map[string]Perm // regular files by image path; nil if they couldn't be read
	// OtherPartitions says the disk has partitions besides Rootfs, such as a boot partition that
	// may be in a filesystem trowl can't read.
	OtherPartitions bool
}

// Perm is a file's owner and mode as the image records them. The extracted copy can't keep them:
// without root, every file ends up owned by whoever runs trowl.
type Perm struct{ Mode, UID, GID int }

func magic(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b := make([]byte, n)
	m, _ := io.ReadFull(f, b)
	return b[:m]
}

func decompress(src, work string) (string, string, error) {
	head := magic(src, 8)
	dst := filepath.Join(work, filepath.Base(src)+".raw")
	if bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		if _, err := exec.LookPath("zstd"); err != nil {
			return "", "", errorf("zstd is required to read .zst images")
		}
		out, err := os.Create(dst)
		if err != nil {
			return "", "", err
		}
		defer out.Close()
		cmd := exec.Command("zstd", "-dcq", src)
		cmd.Stdout = out
		if err := cmd.Run(); err != nil {
			return "", "", errorf("zstd can't read the image; it may be corrupt")
		}
		return dst, "zstd", nil
	}
	var kind string
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		kind = "gzip"
	case bytes.HasPrefix(head, []byte("\xfd7zXZ\x00")):
		kind = "xz"
	case bytes.HasPrefix(head, []byte("BZh")):
		kind = "bzip2"
	default:
		return "", "", nil
	}
	in, err := os.Open(src)
	if err != nil {
		return "", "", err
	}
	defer in.Close()
	var r io.Reader
	switch kind {
	case "gzip":
		r, err = gzip.NewReader(in)
	case "xz":
		r, err = xz.NewReader(in)
	case "bzip2":
		r = bzip2.NewReader(in)
	}
	if err != nil {
		return "", "", err
	}
	out, err := os.Create(dst)
	if err != nil {
		return "", "", err
	}
	defer out.Close()
	if _, err := io.CopyBuffer(out, r, make([]byte, 1<<20)); err != nil {
		return "", "", err
	}
	return dst, kind, nil
}

func isExt(path string) bool {
	h := magic(path, 1082)
	return len(h) >= 1082 && h[1080] == 0x53 && h[1081] == 0xef
}

func isSquashfs(path string) bool {
	h := string(magic(path, 4))
	return h == "hsqs" || h == "sqsh"
}

func isTar(path string) bool {
	h := magic(path, 512)
	return len(h) >= 262 && string(h[257:262]) == "ustar"
}

// partitions returns (offset, size) in bytes for each partition of an MBR or GPT disk image.
func partitions(path string) [][2]int64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	mbr := make([]byte, sector)
	if n, _ := io.ReadFull(f, mbr); n < sector || mbr[510] != 0x55 || mbr[511] != 0xaa {
		return nil
	}
	type ent struct {
		ptype       byte
		start, size uint32
	}
	var entries []ent
	gpt := false
	for i := 0; i < 4; i++ {
		e := mbr[446+16*i:]
		entries = append(entries, ent{e[4], binary.LittleEndian.Uint32(e[8:]), binary.LittleEndian.Uint32(e[12:])})
		if e[4] == 0xee {
			gpt = true
		}
	}
	if gpt {
		hdr := make([]byte, 92)
		f.Seek(sector, io.SeekStart)
		if n, _ := io.ReadFull(f, hdr); n < 92 || string(hdr[:8]) != "EFI PART" {
			return nil
		}
		lba := binary.LittleEndian.Uint64(hdr[72:])
		count := binary.LittleEndian.Uint32(hdr[80:])
		esize := binary.LittleEndian.Uint32(hdr[84:])
		table := make([]byte, int(count)*int(esize))
		f.Seek(int64(lba)*sector, io.SeekStart)
		n, _ := io.ReadFull(f, table)
		table = table[:n]
		var parts [][2]int64
		for i := 0; i < int(count); i++ {
			lo, hi := i*int(esize), (i+1)*int(esize)
			if hi > len(table) {
				break
			}
			e := table[lo:hi]
			if bytes.Equal(e[:16], make([]byte, 16)) {
				continue
			}
			first := binary.LittleEndian.Uint64(e[32:])
			last := binary.LittleEndian.Uint64(e[40:])
			parts = append(parts, [2]int64{int64(first) * sector, int64(last-first+1) * sector})
		}
		return parts
	}
	// Plain MBR; extended partitions are not followed (rare in embedded images).
	var parts [][2]int64
	for _, e := range entries {
		if e.ptype != 0 && e.ptype != 0x05 && e.ptype != 0x0f {
			parts = append(parts, [2]int64{int64(e.start) * sector, int64(e.size) * sector})
		}
	}
	return parts
}

func carve(path string, offset, size int64, dst string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := in.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	_, err = io.CopyN(out, in, size)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return err
}

func extractExt(img, dest string) (map[string]Perm, error) {
	if _, err := exec.LookPath("debugfs"); err != nil {
		return nil, errorf("debugfs (e2fsprogs) is required to read ext2/3/4 images")
	}
	entries, err := extList(img)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(img)
	if err != nil {
		return nil, err
	}
	os.MkdirAll(dest, 0o755)
	var stderr bytes.Buffer
	cmd := exec.Command("debugfs", "-R", "rdump / .", abs)
	cmd.Dir = dest
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, errorf("debugfs failed: %s", strings.TrimSpace(stderr.String()))
	}
	// debugfs exits 0 after failing to write a file, and escapes names outside plain ASCII.
	sizes := map[string]int64{}
	for _, e := range entries {
		if e.mode&0o170000 == 0o100000 && !strings.Contains(e.path, "M-") && !strings.Contains(e.path, "^") {
			sizes[e.path] = e.size
		}
	}
	if err := checkExtracted(dest, sizes); err != nil {
		return nil, err
	}
	return extPerms(entries), nil
}

// checkExtracted compares the extracted files with their listing, by image path and size, as
// the tools can leave some out or cut short without failing. A file that can't be looked at
// because of its directory's mode isn't counted.
func checkExtracted(dest string, sizes map[string]int64) error {
	lost := 0
	for p, size := range sizes {
		st, err := os.Lstat(filepath.Join(dest, p))
		if errors.Is(err, fs.ErrNotExist) || (err == nil && st.Size() != size) {
			lost++
		}
	}
	if lost > 0 {
		return errorf("%d of %d files could not be extracted; the image may be corrupt", lost, len(sizes))
	}
	return nil
}

// extEntry is one line of debugfs "ls -p" with the path it was found at.
type extEntry struct {
	inode, mode, uid, gid int
	size                  int64
	path                  string
}

func (e extEntry) isDir() bool { return e.mode&0o170000 == 0o040000 }

var (
	extPromptRe = regexp.MustCompile(`^debugfs: ls -p <(\d+)>$`)
	// extEntryRe matches a line of debugfs "ls -p": /inode/mode/uid/gid/name/size/.
	extEntryRe = regexp.MustCompile(`^/(\d+)/(\d+)/(\d+)/(\d+)/(.*)/(\d*)/$`)
)

const extRootInode = 2

// extList walks the image and refuses one that rdump can't extract safely. debugfs is only ever
// given inode numbers: it runs lines starting "!" in a shell and doesn't check names, so a name
// from the image must not reach its command line or rdump's output path.
func extList(img string) ([]extEntry, error) {
	var entries []extEntry
	seen := map[int]bool{extRootInode: true}
	dirs := map[int]string{extRootInode: "/"}
	for len(dirs) > 0 {
		var cmds strings.Builder
		for inode := range dirs {
			fmt.Fprintf(&cmds, "ls -p <%d>\n", inode)
		}
		var stderr bytes.Buffer
		cmd := exec.Command("debugfs", "-f", "-", img)
		cmd.Stdin = strings.NewReader(cmds.String())
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, errorf("debugfs failed: %s", strings.TrimSpace(stderr.String()))
		}
		found, err := parseExtList(string(out), dirs)
		if err != nil {
			return nil, err
		}
		entries = append(entries, found...)
		dirs = map[int]string{}
		for _, e := range found {
			if !e.isDir() {
				continue
			}
			if seen[e.inode] {
				return nil, errorf("unsafe image: directory %q is linked twice", e.path)
			}
			seen[e.inode] = true
			dirs[e.inode] = e.path
		}
	}
	return entries, nil
}

// parseExtList reads the listings of dirs, an inode to path map. debugfs prints names raw, so a
// line that isn't exactly an entry means a name holds a line break, which could hide anything.
func parseExtList(out string, dirs map[int]string) ([]extEntry, error) {
	var entries []extEntry
	dir, listed := "", 0
	names := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if m := extPromptRe.FindStringSubmatch(line); m != nil {
			inode, _ := strconv.Atoi(m[1])
			d, ok := dirs[inode]
			if !ok {
				return nil, errorf("unsafe image: unexpected listing in %q", dir)
			}
			dir, listed = d, 0
			names = map[string]bool{}
			continue
		}
		if dir == "" || line == "" {
			continue
		}
		m := extEntryRe.FindStringSubmatch(line)
		if m == nil {
			return nil, errorf("unsafe image: file name with a line break in %q", dir)
		}
		listed++
		name := m[5]
		if (name == "." || name == "..") && listed <= 2 {
			continue
		}
		if name == "" && m[1] == "0" {
			continue // an unused slot, as lost+found is full of
		}
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") || names[name] {
			return nil, errorf("unsafe image: bad entry %q in %q", name, dir)
		}
		names[name] = true
		inode, _ := strconv.Atoi(m[1])
		mode, _ := strconv.ParseInt(m[2], 8, 32)
		uid, _ := strconv.Atoi(m[3])
		gid, _ := strconv.Atoi(m[4])
		size, _ := strconv.ParseInt(m[6], 10, 64)
		entries = append(entries, extEntry{inode, int(mode), uid, gid, size, path.Join(dir, name)})
	}
	return entries, nil
}

func extPerms(entries []extEntry) map[string]Perm {
	perms := map[string]Perm{}
	for _, e := range entries {
		if e.mode&0o170000 == 0o100000 {
			perms[e.path] = Perm{e.mode & 0o7777, e.uid, e.gid}
		}
	}
	return perms
}

// parseSquashList reads the owner, mode and size of each regular file from lines of unsquashfs's
// numeric listing, such as "-rwsr-xr-x 0/0 59520 2026-10-27 10:00 squashfs-root/bin/su".
func parseSquashList(out string) (map[string]Perm, map[string]int64) {
	perms, sizes := map[string]Perm{}, map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || len(f[0]) != 10 || f[0][0] != '-' {
			continue
		}
		var uid, gid int
		if n, _ := fmt.Sscanf(f[1], "%d/%d", &uid, &gid); n != 2 {
			continue
		}
		name := strings.TrimPrefix(strings.Join(f[5:], " "), "squashfs-root")
		perms[name] = Perm{symbolicMode(f[0]), uid, gid}
		sizes[name], _ = strconv.ParseInt(f[2], 10, 64)
	}
	return perms, sizes
}

// symbolicMode turns "-rwsr-xr-x" into 0o4755.
func symbolicMode(s string) int {
	mode := 0
	for i, c := range s[1:] {
		if c != '-' && c != 'S' && c != 'T' {
			mode |= 1 << (8 - i)
		}
	}
	for i, bit := range map[int]int{3: 0o4000, 6: 0o2000, 9: 0o1000} {
		if s[i] == 's' || s[i] == 'S' || s[i] == 't' || s[i] == 'T' {
			mode |= bit
		}
	}
	return mode
}

// dirPerms reads an unpacked directory, which keeps whatever owners it was unpacked with.
func dirPerms(root string) map[string]Perm {
	perms := map[string]Perm{}
	IterFiles(root, func(imagePath, real string) {
		if st, err := os.Lstat(real); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				perms[imagePath] = Perm{int(sys.Mode & 0o7777), int(sys.Uid), int(sys.Gid)}
			}
		}
	})
	return perms
}

func extractSquashfs(img, dest string) (map[string]Perm, error) {
	if _, err := exec.LookPath("unsquashfs"); err != nil {
		return nil, errorf("unsquashfs (squashfs-tools) is required to read squashfs images")
	}
	out, err := exec.Command("unsquashfs", "-lln", img).Output()
	if err != nil {
		return nil, errorf("unsquashfs can't read the image; it may be corrupt")
	}
	perms, sizes := parseSquashList(string(out))
	// -no-xattrs/-ignore-errors: device nodes and xattrs can't be created without root, so the
	// exit status can't tell those from a lost file. checkExtracted does.
	exec.Command("unsquashfs", "-no-xattrs", "-ignore-errors", "-quiet", "-f", "-d", dest, img).Run()
	if !py.IsDir(dest) {
		return nil, errorf("unsquashfs produced no output")
	}
	return perms, checkExtracted(dest, sizes)
}

func looksLikeRootfs(path string) bool {
	return py.IsDir(py.InRoot(path, "etc")) &&
		(py.IsDir(py.InRoot(path, "usr")) || py.Exists(py.InRoot(path, "bin")))
}

func extractFilesystem(img, dest string) (string, map[string]Perm, error) {
	if isExt(img) {
		perms, err := extractExt(img, dest)
		return "ext", perms, err
	}
	if isSquashfs(img) {
		perms, err := extractSquashfs(img, dest)
		return "squashfs", perms, err
	}
	return "", nil, nil
}

// Unpack unpacks image under workdir (a temp dir if empty) and returns the rootfs path.
func Unpack(image, workdir string) (*Unpacked, error) {
	if py.IsDir(image) {
		return &Unpacked{Rootfs: image, SourceFormat: "directory", Perms: dirPerms(image)}, nil
	}
	if !py.IsFile(image) {
		return nil, errorf("no such image: %s", py.CleanPath(image))
	}
	work := workdir
	if work == "" {
		var err error
		if work, err = os.MkdirTemp("", "trowl-"); err != nil {
			return nil, err
		}
	}
	os.MkdirAll(work, 0o755)
	notes := []string{}
	var formats []string

	current := py.Resolve(image)
	for {
		dec, kind, err := decompress(current, work)
		if err != nil {
			return nil, err
		}
		if dec == "" {
			break
		}
		current = dec
		formats = append(formats, kind)
	}

	dest := filepath.Join(work, "rootfs")
	kind, perms, err := extractFilesystem(current, dest)
	if err != nil {
		return nil, err
	}
	if kind != "" {
		formats = append(formats, kind)
		return &Unpacked{Rootfs: dest, SourceFormat: strings.Join(formats, "+"), Notes: notes, Perms: perms}, nil
	}

	if isTar(current) {
		skipped, perms, err := extractTar(current, dest)
		if err != nil {
			return nil, err
		}
		formats = append(formats, "tar")
		if skipped > 0 {
			notes = append(notes, fmt.Sprintf("%d tar members skipped (device nodes, links outside root)", skipped))
		}
		return &Unpacked{Rootfs: dest, SourceFormat: strings.Join(formats, "+"), Notes: notes, Perms: perms}, nil
	}

	parts := partitions(current)
	if len(parts) == 0 {
		return nil, errorf("unrecognised image format: %s", py.CleanPath(image))
	}
	formats = append(formats, "disk")
	chosen := ""
	var chosenPerms map[string]Perm
	for i, p := range parts {
		n := i + 1
		partImg := filepath.Join(work, fmt.Sprintf("part%d.img", n))
		if err := carve(current, p[0], p[1], partImg); err != nil {
			return nil, err
		}
		partDir := filepath.Join(work, fmt.Sprintf("part%d", n))
		kind, perms, err := extractFilesystem(partImg, partDir)
		os.Remove(partImg)
		if err != nil {
			return nil, err
		}
		if kind == "" {
			notes = append(notes, fmt.Sprintf("partition %d: unsupported filesystem, skipped", n))
			continue
		}
		if chosen == "" && looksLikeRootfs(partDir) {
			chosen, chosenPerms = partDir, perms
			formats = append(formats, fmt.Sprintf("p%d:%s", n, kind))
		} else {
			notes = append(notes, fmt.Sprintf("partition %d (%s) extracted to %s", n, kind, partDir))
		}
	}
	if chosen == "" {
		return nil, errorf("no partition looks like a root filesystem")
	}
	return &Unpacked{Rootfs: chosen, SourceFormat: strings.Join(formats, "+"), Notes: notes, Perms: chosenPerms,
		OtherPartitions: len(parts) > 1}, nil
}

// IterFiles calls fn(imagePath, realPath) for regular files, never following symlinks, in the
// order os.walk visits them: each directory's files in directory order, then its subdirectories.
func IterFiles(rootfs string, fn func(imagePath, real string)) {
	var walk func(dir, rel string)
	walk = func(dir, rel string) {
		f, err := os.Open(dir)
		if err != nil {
			return
		}
		entries, _ := f.ReadDir(-1) // unsorted: the filesystem's own order, as os.scandir gives it
		f.Close()
		var dirs []string
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			isDir := e.IsDir()
			if e.Type()&os.ModeSymlink != 0 {
				isDir = py.IsDir(full) // os.walk files a symlink to a directory under dirnames
			}
			if isDir {
				if e.Type()&os.ModeSymlink == 0 {
					dirs = append(dirs, e.Name())
				}
				continue
			}
			if e.Type()&os.ModeSymlink != 0 || !py.IsFile(full) {
				continue
			}
			name := e.Name()
			if rel != "" {
				name = rel + "/" + name
			}
			fn("/"+name, full)
		}
		for _, d := range dirs {
			sub := d
			if rel != "" {
				sub = rel + "/" + d
			}
			walk(filepath.Join(dir, d), sub)
		}
	}
	walk(rootfs, "")
}
