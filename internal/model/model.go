// Package model holds shared result types. Every check emits Findings; the report is plain JSON.
package model

import (
	"runtime/debug"
	"strings"

	"github.com/corefense/trowl/internal/pyjson"
)

// version is set at build time with -ldflags "-X .../internal/model.version=v1.2.3"; the
// Dockerfile and the release workflow pass the git tag. Without it, the version comes from the
// Go build info: the module version for "go install", or the VCS revision for a local build.
var version string

// Version is what the tool reports, e.g. "0.2.0" or "0.1.0-dev+a1b2c3d".
var Version = resolveVersion()

const devVersion = "0.1.0-dev"

func resolveVersion() string {
	if version != "" {
		return strings.TrimPrefix(version, "v")
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return devVersion
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return strings.TrimPrefix(v, "v")
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return devVersion
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if dirty {
		rev += ".dirty"
	}
	return devVersion + "+" + rev
}

var Severities = []string{"info", "low", "medium", "high", "critical"}

func SeverityRank(sev string) int {
	for i, s := range Severities {
		if s == sev {
			return i
		}
	}
	return -1
}

type Finding struct {
	Check    string // e.g. "secrets.private-key", "elf.pie", "fstab.nosuid"
	Severity string
	Path     string // path inside the image ("/usr/bin/foo"), or "" for image-wide findings
	Title    string
	Detail   string
	Evidence *pyjson.Obj
}

func (f Finding) Obj() *pyjson.Obj {
	ev := f.Evidence
	if ev == nil {
		ev = pyjson.New()
	}
	return pyjson.O("check", f.Check, "severity", f.Severity, "path", f.Path, "title", f.Title,
		"detail", f.Detail, "evidence", ev)
}
