// Package inventory lists the source components installed in a rootfs from its package database,
// for CVE matching when no SBOM is given. Images built without package management have none.
package inventory

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Component is one source component and its upstream version.
type Component struct{ Name, Version string }

// Read returns the installed components and the database they came from ("rpm", "opkg" or
// "dpkg"), or nil and "" when the image has no database that can be read.
func Read(rootfs string) ([]Component, string) {
	for _, s := range []struct{ path, name string }{
		{"var/lib/opkg/status", "opkg"}, {"usr/lib/opkg/status", "opkg"}, {"var/lib/dpkg/status", "dpkg"},
	} {
		if raw, err := os.ReadFile(filepath.Join(rootfs, s.path)); err == nil {
			if c := parseStatus(string(raw)); len(c) > 0 {
				return c, s.name
			}
		}
	}
	for _, p := range []string{"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"} {
		if c := readRpm(filepath.Join(rootfs, p)); len(c) > 0 {
			return c, "rpm"
		}
	}
	return nil, ""
}

// parseStatus reads an opkg or dpkg status file. A package names its source in Source: a recipe
// file for opkg ("busybox_1.37.0.bb"), a package name for dpkg ("glibc (2.36-9)").
func parseStatus(text string) []Component {
	found := map[string]string{}
	for _, block := range strings.Split(text, "\n\n") {
		f := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, ": "); ok && !strings.HasPrefix(line, " ") {
				f[k] = v
			}
		}
		if f["Package"] == "" || f["Version"] == "" || !strings.HasSuffix(f["Status"], " installed") {
			continue
		}
		name := f["Package"]
		if src := strings.Fields(f["Source"]); len(src) > 0 {
			name = strings.TrimSuffix(filepath.Base(src[0]), ".bb")
			name, _, _ = strings.Cut(name, "_")
		}
		found[name] = upstream(f["Version"])
	}
	return sorted(found)
}

// upstream drops a package version's epoch and packaging revision: 1:2.36-r0 is 2.36.
func upstream(v string) string {
	if _, rest, ok := strings.Cut(v, ":"); ok {
		v = rest
	}
	if i := strings.LastIndex(v, "-"); i > 0 {
		v = v[:i]
	}
	return v
}

var sourceRpm = regexp.MustCompile(`^(.+)-([^-]+)-[^-]+\.src\.rpm$`)

// readRpm lists source packages from an rpm SQLite database, using the sqlite3 tool.
func readRpm(path string) []Component {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		fmt.Fprintln(os.Stderr, "trowl: sqlite3 is required to read the rpm database; packages not checked")
		return nil
	}
	out, err := exec.Command("sqlite3", "file:"+path+"?immutable=1", "select hex(blob) from Packages").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "trowl: reading the rpm database: %v\n", err)
		return nil
	}
	found := map[string]string{}
	for _, line := range strings.Fields(string(out)) {
		blob, err := hex.DecodeString(line)
		if err != nil {
			continue
		}
		// Source packages are what CVEs are filed against; gpg-pubkey entries have none.
		if m := sourceRpm.FindStringSubmatch(headerString(blob, 1044)); m != nil {
			found[m[1]] = m[2]
		}
	}
	return sorted(found)
}

// headerString reads a string tag from an rpm header blob: an entry count, a data size, 16-byte
// index entries (tag, type, offset, count), then the data.
func headerString(b []byte, tag uint32) string {
	if len(b) < 8 {
		return ""
	}
	n := int(binary.BigEndian.Uint32(b))
	base := 8 + 16*n
	if base > len(b) {
		return ""
	}
	for i := 0; i < n; i++ {
		e := b[8+16*i:]
		if binary.BigEndian.Uint32(e) != tag {
			continue
		}
		off := base + int(binary.BigEndian.Uint32(e[8:]))
		if off >= len(b) {
			return ""
		}
		s := string(b[off:])
		end := strings.IndexByte(s, 0)
		if end < 0 {
			return ""
		}
		return s[:end]
	}
	return ""
}

func sorted(found map[string]string) []Component {
	out := make([]Component, 0, len(found))
	for n, v := range found {
		out = append(out, Component{n, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
