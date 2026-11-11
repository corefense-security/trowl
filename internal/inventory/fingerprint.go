package inventory

// Fingerprints recognise installed packages from the binaries themselves, for an image
// with neither an SBOM nor a package database. Each file in fingerprints/ describes one upstream
// package: which files to look at, the pattern that finds its version in them, and the CPE its
// CVEs are filed under. fingerprints/README.md documents the format and the packages covered.
//
// This finds a version and knows nothing of the build. A CVE fixed by a patch backported without
// a version change still matches. The report says so.

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// FromBinaries is the inventory source when components were recognised by the fingerprints.
const FromBinaries = "binaries"

// maxFingerprintBytes bounds how much of one file is read. Executables and libraries are far
// smaller, so a bigger file isn't one the fingerprints are for.
const maxFingerprintBytes = 64 << 20

//go:embed fingerprints/*.yaml
var fingerprintFiles embed.FS

// Found is a package recognised from the binaries.
type Found struct {
	Name, Version string
	CPEs          []string // the fingerprint's CPEs with this version filled in
	Files         []string // where it was recognised, as paths in the image ("/usr/sbin/sshd")
}

type fingerprint struct {
	Package  string     `yaml:"package"`
	CPEs     []string   `yaml:"cpes"`
	Evidence []evidence `yaml:"evidence"`
	Examples []example  `yaml:"examples"` // checked by the tests
	Rejects  []example  `yaml:"rejects"`  // checked by the tests, and must give no version
	file     string     // the fingerprint's own file name, for error messages
}

// evidence is one way to find the version, either in the bytes of matching files (Pattern) or in
// the file name itself (NamePattern). Exactly one of the two is set.
type evidence struct {
	Files       []string `yaml:"files"` // file-name globs, path.Match syntax
	Pattern     string   `yaml:"pattern"`
	NamePattern string   `yaml:"name_pattern"`
	re          *regexp.Regexp
	version     int    // index of the "version" group in re, or -1 when parts gives it
	parts       [3]int // indexes of the "major", "minor" and "patch" groups, when used instead
}

type example struct {
	File     string `yaml:"file"`
	Contains string `yaml:"contains"`
	Version  string `yaml:"version"`
}

// loadFingerprints parses and checks the embedded fingerprint files once.
var loadFingerprints = sync.OnceValues(func() ([]*fingerprint, error) {
	entries, err := fingerprintFiles.ReadDir("fingerprints")
	if err != nil {
		return nil, err
	}
	var out []*fingerprint
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := fingerprintFiles.ReadFile("fingerprints/" + e.Name())
		if err != nil {
			return nil, err
		}
		c := &fingerprint{file: e.Name()}
		if err := yaml.Unmarshal(raw, c); err != nil {
			return nil, fmt.Errorf("fingerprint %s: %w", e.Name(), err)
		}
		if err := c.prepare(); err != nil {
			return nil, fmt.Errorf("fingerprint %s: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	return out, nil
})

// prepare checks a fingerprint and compiles its patterns.
func (c *fingerprint) prepare() error {
	if c.Package == "" {
		return fmt.Errorf("no package name")
	}
	if len(c.CPEs) == 0 {
		return fmt.Errorf("no cpes")
	}
	for _, cpe := range c.CPEs {
		// The version and the fields after it are filled in from the match.
		if f := strings.Split(cpe, ":"); len(f) != 5 || f[0] != "cpe" || f[1] != "2.3" || f[3] == "" || f[4] == "" {
			return fmt.Errorf("cpe %q: want cpe:2.3:<part>:<vendor>:<product>", cpe)
		}
	}
	if len(c.Evidence) == 0 {
		return fmt.Errorf("no evidence")
	}
	if len(c.Examples) == 0 {
		return fmt.Errorf("no examples")
	}
	for i := range c.Evidence {
		ev := &c.Evidence[i]
		if len(ev.Files) == 0 {
			return fmt.Errorf("evidence %d: no files", i+1)
		}
		for _, g := range ev.Files {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("evidence %d: file glob %q: %w", i+1, g, err)
			}
		}
		pattern := ev.Pattern
		if (ev.Pattern == "") == (ev.NamePattern == "") {
			return fmt.Errorf("evidence %d: set exactly one of pattern and name_pattern", i+1)
		}
		if pattern == "" {
			pattern = ev.NamePattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("evidence %d: %w", i+1, err)
		}
		// The pattern needs a version group, or major/minor/patch groups for a version stored as
		// packed numbers (acl's library revision 2302 for 2.3.2). The parts are joined with dots,
		// with leading zeros dropped.
		ev.version = re.SubexpIndex("version")
		ev.parts = [3]int{re.SubexpIndex("major"), re.SubexpIndex("minor"), re.SubexpIndex("patch")}
		if ev.version < 0 && (ev.parts[0] < 0 || ev.parts[1] < 0 || ev.parts[2] < 0) {
			return fmt.Errorf("evidence %d: pattern needs a (?P<version>...) group, or major, minor and patch groups", i+1)
		}
		ev.re = re
	}
	return nil
}

// versionOf returns the version c finds in the file named name, or "". content returns the file's
// bytes, read at most once by the caller and only when a glob matches. nil means unreadable.
func (c *fingerprint) versionOf(name string, content func() []byte) string {
	for i := range c.Evidence {
		ev := &c.Evidence[i]
		if !matchesAny(ev.Files, name) {
			continue
		}
		var m [][]byte
		if ev.NamePattern != "" {
			m = ev.re.FindSubmatch([]byte(name))
		} else if data := content(); data != nil {
			m = ev.re.FindSubmatch(data)
		}
		if m == nil {
			continue
		}
		if ev.version < 0 {
			return joinParts(m, ev.parts)
		}
		// Yocto versions carry a source-control suffix (2.43+git) that CVE data never uses.
		if v, _, _ := strings.Cut(string(m[ev.version]), "+"); v != "" {
			return v
		}
	}
	return ""
}

// joinParts builds a version from major, minor and patch groups, so "2", "3", "02" gives 2.3.2.
func joinParts(m [][]byte, parts [3]int) string {
	out := make([]string, 3)
	for i, g := range parts {
		n, err := strconv.Atoi(string(m[g]))
		if err != nil {
			return ""
		}
		out[i] = strconv.Itoa(n)
	}
	return strings.Join(out, ".")
}

func matchesAny(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// cpesFor fills a version into the fingerprint's CPEs.
func (c *fingerprint) cpesFor(version string) []string {
	out := make([]string, len(c.CPEs))
	for i, cpe := range c.CPEs {
		out[i] = cpe + ":" + version + ":*:*:*:*:*:*:*"
	}
	return out
}

var elfMagic = []byte("\x7fELF")

// readELF returns an ELF file's contents, or nil for anything else, an unreadable file or one
// over the size bound.
func readELF(p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFingerprintBytes+1))
	if err != nil || len(data) > maxFingerprintBytes || !bytes.HasPrefix(data, elfMagic) {
		return nil
	}
	return data
}

// Fingerprint walks the rootfs and returns the packages the fingerprints recognise, one entry per
// package and version (an image can hold two versions of a library), sorted by name. Symbolic
// links are skipped, since the file they point to is read under its own name.
func Fingerprint(rootfs string) ([]Found, error) {
	fingerprints, err := loadFingerprints()
	if err != nil {
		return nil, err
	}
	type key struct{ name, version string }
	found := map[key]*Found{}
	err = filepath.WalkDir(rootfs, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil // an unreadable directory loses only what is under it
		}
		var data []byte
		read := false
		content := func() []byte {
			if !read {
				data, read = readELF(p), true
			}
			return data
		}
		for _, c := range fingerprints {
			v := c.versionOf(d.Name(), content)
			// A name-only match must still be an ELF file, since a linker script can be named like a library.
			if v == "" || content() == nil {
				continue
			}
			k := key{c.Package, v}
			if found[k] == nil {
				found[k] = &Found{Name: c.Package, Version: v, CPEs: c.cpesFor(v)}
			}
			rel, _ := filepath.Rel(rootfs, p)
			found[k].Files = append(found[k].Files, "/"+filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]Found, 0, len(found))
	for _, f := range found {
		sort.Strings(f.Files)
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}
