// Package py holds small helpers that reproduce Python standard-library behaviour the original
// implementation relied on (text decoding, splitlines, round, path ordering, base64).
package py

import (
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DecodeReplace decodes UTF-8 like bytes.decode(errors="replace"). Each invalid byte becomes U+FFFD.
func DecodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			sb.WriteRune(utf8.RuneError)
			b = b[1:]
			continue
		}
		sb.WriteRune(r)
		b = b[size:]
	}
	return sb.String()
}

// Latin1 decodes bytes as ISO-8859-1.
func Latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func isLineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// SplitLines mirrors str.splitlines().
func SplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if isLineBreak(r) {
			out = append(out, s[start:i])
			i += size
			if r == '\r' && i < len(s) && s[i] == '\n' {
				i++
			}
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// IsSpace mirrors str.isspace() for one rune.
func IsSpace(r rune) bool {
	return unicode.IsSpace(r) || r == 0x1c || r == 0x1d || r == 0x1e || r == 0x1f
}

// Strip mirrors str.strip().
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// Fields mirrors str.split() with no arguments.
func Fields(s string) []string { return strings.FieldsFunc(s, IsSpace) }

// Round2 mirrors round(x, 2).
func Round2(x float64) float64 { return math.RoundToEven(x*100) / 100 }

// CleanPath mirrors str(pathlib.Path(p)): collapses repeated slashes and "." parts, drops a
// trailing slash, keeps "..".
func CleanPath(p string) string {
	if p == "" {
		return "."
	}
	abs := strings.HasPrefix(p, "/")
	var parts []string
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." {
			continue
		}
		parts = append(parts, s)
	}
	j := strings.Join(parts, "/")
	switch {
	case abs && strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///"):
		return "//" + j
	case abs:
		return "/" + j
	case j == "":
		return "."
	}
	return j
}

// SortPaths orders paths by their components, like sorted() over pathlib.Path objects.
func SortPaths(paths []string) {
	sort.SliceStable(paths, func(i, j int) bool {
		a, b := strings.Split(paths[i], string(filepath.Separator)), strings.Split(paths[j], string(filepath.Separator))
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
}

// IsSymlink is Path.is_symlink().
func IsSymlink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

// IsFile is Path.is_file() (follows symlinks, regular files only).
func IsFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// IsDir is Path.is_dir().
func IsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// Exists is Path.exists().
func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Resolve mirrors Path.resolve(strict=False). It makes p absolute and resolves symlinks as far as
// the path exists.
func Resolve(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	dir, base := filepath.Split(abs)
	dir = filepath.Clean(dir)
	if dir == abs || dir == "/" {
		return abs
	}
	return filepath.Join(Resolve(dir), base)
}

const maxLinks = 40

// InRoot is where path p inside an unpacked image really is. Links are followed as the image
// would follow them. An absolute link starts again at root and ".." stops there, so no link in
// the image can lead to the host. A missing part is left as it is. Too many links give a path
// that can't exist, as the last link may still point out of the image.
func InRoot(root, p string) string {
	cur := "/"
	parts := strings.Split(p, "/")
	for links := 0; len(parts) > 0; {
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, part)
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil {
			cur = next
			continue
		}
		if links++; links > maxLinks {
			return filepath.Join(root, "\x00")
		}
		if strings.HasPrefix(target, "/") {
			cur = "/"
		}
		parts = append(strings.Split(target, "/"), parts...)
	}
	return filepath.Join(root, cur)
}

var b64 = func() [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = 0xff
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		t[c] = byte(i)
	}
	return t
}()

// B64DecodeLenient mirrors base64.b64decode(s, validate=False) (CPython binascii.a2b_base64,
// non-strict). ok is false where Python raises binascii.Error.
func B64DecodeLenient(s []byte) (out []byte, ok bool) {
	quad, pads := 0, 0
	var left byte
	for _, c := range s {
		if c == '=' {
			pads++
			if quad >= 2 && quad+pads >= 4 {
				return out, true
			}
			continue
		}
		v := b64[c]
		if v == 0xff {
			continue
		}
		pads = 0
		switch quad {
		case 0:
			quad, left = 1, v
		case 1:
			quad = 2
			out = append(out, left<<2|v>>4)
			left = v & 0x0f
		case 2:
			quad = 3
			out = append(out, left<<4|v>>2)
			left = v & 0x03
		case 3:
			quad = 0
			out = append(out, left<<6|v)
			left = 0
		}
	}
	return out, quad == 0
}
