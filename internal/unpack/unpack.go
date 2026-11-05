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
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
}

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
			return "", "", err
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

func extractExt(img, dest string) error {
	if _, err := exec.LookPath("debugfs"); err != nil {
		return errorf("debugfs (e2fsprogs) is required to read ext2/3/4 images")
	}
	os.MkdirAll(dest, 0o755)
	var stderr bytes.Buffer
	cmd := exec.Command("debugfs", "-R", "rdump / "+dest, img)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errorf("debugfs failed: %s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

func extractSquashfs(img, dest string) error {
	if _, err := exec.LookPath("unsquashfs"); err != nil {
		return errorf("unsquashfs (squashfs-tools) is required to read squashfs images")
	}
	// -no-xattrs/-ignore-errors: device nodes and xattrs can't be created without root.
	exec.Command("unsquashfs", "-no-xattrs", "-ignore-errors", "-quiet", "-f", "-d", dest, img).Run()
	if !py.IsDir(dest) {
		return errorf("unsquashfs produced no output")
	}
	return nil
}

func looksLikeRootfs(path string) bool {
	return py.IsDir(filepath.Join(path, "etc")) &&
		(py.IsDir(filepath.Join(path, "usr")) || py.Exists(filepath.Join(path, "bin")))
}

func extractFilesystem(img, dest string) (string, error) {
	if isExt(img) {
		return "ext", extractExt(img, dest)
	}
	if isSquashfs(img) {
		return "squashfs", extractSquashfs(img, dest)
	}
	return "", nil
}

// Unpack unpacks image under workdir (a temp dir if empty) and returns the rootfs path.
func Unpack(image, workdir string) (*Unpacked, error) {
	if py.IsDir(image) {
		return &Unpacked{Rootfs: image, SourceFormat: "directory"}, nil
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
	fs, err := extractFilesystem(current, dest)
	if err != nil {
		return nil, err
	}
	if fs != "" {
		formats = append(formats, fs)
		return &Unpacked{Rootfs: dest, SourceFormat: strings.Join(formats, "+"), Notes: notes}, nil
	}

	if isTar(current) {
		skipped, err := extractTar(current, dest)
		if err != nil {
			return nil, err
		}
		formats = append(formats, "tar")
		if skipped > 0 {
			notes = append(notes, fmt.Sprintf("%d tar members skipped (device nodes, links outside root)", skipped))
		}
		return &Unpacked{Rootfs: dest, SourceFormat: strings.Join(formats, "+"), Notes: notes}, nil
	}

	parts := partitions(current)
	if len(parts) == 0 {
		return nil, errorf("unrecognised image format: %s", py.CleanPath(image))
	}
	formats = append(formats, "disk")
	chosen := ""
	for i, p := range parts {
		n := i + 1
		partImg := filepath.Join(work, fmt.Sprintf("part%d.img", n))
		if err := carve(current, p[0], p[1], partImg); err != nil {
			return nil, err
		}
		partDir := filepath.Join(work, fmt.Sprintf("part%d", n))
		fs, err := extractFilesystem(partImg, partDir)
		os.Remove(partImg)
		if err != nil {
			return nil, err
		}
		if fs == "" {
			notes = append(notes, fmt.Sprintf("partition %d: unsupported filesystem, skipped", n))
			continue
		}
		if chosen == "" && looksLikeRootfs(partDir) {
			chosen = partDir
			formats = append(formats, fmt.Sprintf("p%d:%s", n, fs))
		} else {
			notes = append(notes, fmt.Sprintf("partition %d (%s) extracted to %s", n, fs, partDir))
		}
	}
	if chosen == "" {
		return nil, errorf("no partition looks like a root filesystem")
	}
	return &Unpacked{Rootfs: chosen, SourceFormat: strings.Join(formats, "+"), Notes: notes}, nil
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
