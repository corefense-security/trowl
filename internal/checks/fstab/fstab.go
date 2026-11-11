// Package fstab checks mount option hygiene from /etc/fstab.
//
// Only what the image declares is judged. Mounts set up elsewhere (systemd .mount units,
// initramfs scripts) are left for a later pass.
package fstab

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
)

// A read-write mount should carry all of these. The root filesystem needs exec and device
// nodes, so it is judged only on being read-only and nosuid.
var (
	rwFlags   = []string{"nodev", "nosuid", "noexec"}
	rootFlags = []string{"ro", "nosuid"}
	rootMount = regexp.MustCompile(`^/+$`)
)

func Parse(text string) []*pyjson.Obj {
	entries := []*pyjson.Obj{}
	for i, line := range py.SplitLines(text) {
		line = py.Strip(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := py.Fields(line)
		if len(fields) < 3 {
			continue
		}
		opts := []string{"defaults"}
		if len(fields) > 3 {
			opts = strings.Split(fields[3], ",")
		}
		entries = append(entries, pyjson.O("line", i+1, "spec", fields[0], "mountpoint", fields[1],
			"fstype", fields[2], "options", opts))
	}
	return entries
}

// Missing returns the secure flags a mount lacks. A proc mount also needs hidepid, so users
// can't read other users' processes. When it isn't set, "hidepid=1/2" is the suggestion.
func Missing(mp, fstype string, opts []string) []string {
	missing := []string{}
	want := rwFlags
	switch {
	case rootMount.MatchString(mp):
		want = rootFlags
	case contains(opts, "ro"):
		want = nil
	}
	for _, o := range want {
		if !contains(opts, o) {
			missing = append(missing, o)
		}
	}
	if fstype == "proc" && !hidesPids(opts) {
		missing = append(missing, "hidepid=1/2")
	}
	return missing
}

// hidesPids says whether the options set hidepid to anything but 0 ("off" in kernels 5.8+).
func hidesPids(opts []string) bool {
	for _, o := range opts {
		if v, ok := strings.CutPrefix(o, "hidepid="); ok && v != "0" && v != "off" {
			return true
		}
	}
	return false
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func Check(rootfs string) ([]*pyjson.Obj, []model.Finding) {
	path := py.InRoot(rootfs, "etc/fstab")
	if !py.IsFile(path) {
		return []*pyjson.Obj{}, []model.Finding{{Check: "fstab.missing", Path: "/etc/fstab",
			Title: "No /etc/fstab in the image", Detail: "Mount options could not be assessed statically."}}
	}
	raw, _ := os.ReadFile(path)
	entries := Parse(py.DecodeReplace(raw))
	var findings []model.Finding
	for _, e := range entries {
		mp, fstype := e.G("mountpoint").(string), e.G("fstype").(string)
		if fstype == "swap" || mp == "none" {
			continue
		}
		missing := Missing(mp, fstype, e.G("options").([]string))
		e.Set("missing", missing)
		if len(missing) == 0 {
			continue
		}
		findings = append(findings, model.Finding{Check: "fstab.mount-options", Path: "/etc/fstab",
			Title: fmt.Sprintf("%s is missing %s", mp, strings.Join(missing, ", ")),
			Detail: fmt.Sprintf("%s mount at %s (line %d) is missing a secure flag: add %s.", fstype, mp,
				e.G("line").(int), strings.Join(missing, ", ")),
			Evidence: e})
	}
	return entries, findings
}
