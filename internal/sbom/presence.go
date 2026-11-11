package sbom

// Compare what the SBOM declares with what the unpacked image actually contains.
//
// A binary package's presence is decided from the files the SBOM says it contains (path,
// then SHA-256), so no package database is needed in the image. Components that never reach
// the image (build-only recipes, packages whose files are all absent) have their associated
// CVEs reported as candidates for VEX "not_affected / component_not_present".
//
// This is package-level only. A package being absent says nothing about copies of its code
// that were statically linked or vendored into something else.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
)

const maxPaths = 25 // per package, in report evidence

func fileSha256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.CopyBuffer(h, f, make([]byte, 1<<20))
	return hex.EncodeToString(h.Sum(nil))
}

func packageStatus(rootfs string, files []File) (string, *pyjson.Obj) {
	present, modified, missing := 0, 0, 0
	modPaths, missPaths := []string{}, []string{}
	for _, sf := range files {
		name := strings.TrimLeft(sf.Name, "/")
		// The file itself may be a link, which counts as present wherever it points.
		p := filepath.Join(py.InRoot(rootfs, path.Dir(name)), path.Base(name))
		switch {
		case !(py.Exists(p) || py.IsSymlink(p)):
			missing++
			missPaths = append(missPaths, "/"+name)
		case sf.Sha256 != nil && *sf.Sha256 != "" && py.IsFile(p) && !py.IsSymlink(p) && fileSha256(p) != *sf.Sha256:
			modified++
			modPaths = append(modPaths, "/"+name)
		default:
			present++
		}
	}
	if len(modPaths) > maxPaths {
		modPaths = modPaths[:maxPaths]
	}
	if len(missPaths) > maxPaths {
		missPaths = missPaths[:maxPaths]
	}
	counts := pyjson.O("declared", len(files), "present", present, "modified", modified, "missing", missing,
		"modified_paths", modPaths, "missing_paths", missPaths)
	switch {
	case len(files) == 0:
		return "no-files", counts
	case missing == len(files):
		return "absent", counts
	case missing > 0:
		return "partial", counts
	case modified > 0:
		return "modified", counts
	}
	return "present", counts
}

// Status holds each component's presence, as "status" plus "files" (packages) or "outputs"
// (recipes).
type Status struct {
	Keys []string
	M    map[string]*pyjson.Obj
}

func (st *Status) set(id string, o *pyjson.Obj) {
	if _, ok := st.M[id]; !ok {
		st.Keys = append(st.Keys, id)
	}
	st.M[id] = o
}

// Of returns a component's status string, or "" when it has none.
func (st *Status) Of(id string) string {
	if o, ok := st.M[id]; ok {
		return o.G("status").(string)
	}
	return ""
}

type Comparison struct {
	Status     *Status
	NotPresent []any
	Findings   []model.Finding
}

// onBoot reports whether every file is under /boot.
func onBoot(files []File) bool {
	for _, f := range files {
		if !strings.HasPrefix(strings.TrimLeft(f.Name, "/"), "boot/") {
			return false
		}
	}
	return len(files) > 0
}

// Compare returns per-component status, the components not in the image, and findings. With
// otherPartitions, a package whose files are all under /boot can't be called absent. They may be
// on a boot partition, as a kernel's usually are.
func Compare(sb *Sbom, rootfs string, otherPartitions bool) *Comparison {
	status := &Status{M: map[string]*pyjson.Obj{}}
	for _, pid := range sb.PackageOrder {
		pkg := sb.Packages[pid]
		if pkg.Role == "package" {
			st, counts := packageStatus(rootfs, pkg.Files)
			if st == "absent" && otherPartitions && onBoot(pkg.Files) {
				st = "no-files"
			}
			status.set(pid, pyjson.O("status", st, "files", counts))
		}
	}
	producer := map[string]string{}
	for _, r := range sb.Generates.Keys {
		for _, p := range sb.Generates.M[r] {
			producer[p] = r
		}
	}
	inImage := map[string]bool{"present": true, "partial": true, "modified": true}
	for _, rid := range sb.PackageOrder {
		if sb.Packages[rid].Role != "recipe" {
			continue
		}
		outs := sb.Generates.M[rid]
		var outStatus []string
		for _, p := range outs {
			if _, ok := status.M[p]; ok {
				outStatus = append(outStatus, status.Of(p))
			}
		}
		st := "unknown" // only file-less (meta) packages, so the files can't tell
		anyIn, allAbsent := false, true
		for _, s := range outStatus {
			anyIn = anyIn || inImage[s]
			allAbsent = allAbsent && s == "absent"
		}
		switch {
		case len(outs) == 0:
			st = "build-only"
		case anyIn:
			st = "present"
		case allAbsent:
			st = "absent"
		}
		status.set(rid, pyjson.O("status", st, "outputs", len(outs)))
	}

	var findings []model.Finding
	notPresent := []any{}
	for _, pid := range status.Keys {
		info := status.M[pid]
		pkg := sb.Packages[pid]
		st := info.G("status").(string)
		label := strings.TrimSpace(pkg.Name + " " + pkg.Version)
		if pkg.Role == "package" {
			c, _ := info.G("files").(*pyjson.Obj)
			switch st {
			case "absent":
				recipe := pkg.Name
				if r, ok := sb.Packages[producer[pid]]; ok {
					recipe = r.Name
				}
				findings = append(findings, model.Finding{Check: "sbom.package-not-installed", Severity: "medium",
					Title:    fmt.Sprintf("SBOM lists package %s but none of its %d file(s) are in the image", label, c.G("declared").(int)),
					Evidence: pyjson.O("spdxId", pid, "recipe", recipe)})
			case "partial":
				findings = append(findings, model.Finding{Check: "sbom.package-partial", Severity: "low",
					Title:    fmt.Sprintf("Package %s: %d of %d declared file(s) missing", label, c.G("missing").(int), c.G("declared").(int)),
					Evidence: withID(pid, c)})
			case "modified":
				findings = append(findings, model.Finding{Check: "sbom.package-modified", Severity: "info",
					Title:    fmt.Sprintf("Package %s: %d file(s) differ from the SBOM hash", label, c.G("modified").(int)),
					Detail:   "Usually post-install edits (config files, alternatives); check if unexpected.",
					Evidence: withID(pid, c)})
			}
		}
		if pkg.Role == "recipe" && (st == "absent" || st == "build-only") {
			if cves := sb.Vulns.M[pid]; len(cves) > 0 {
				list := []any{}
				for _, c := range cves {
					list = append(list, pyjson.O("id", c, "sbom_vex", sb.Vex(c, pid)))
				}
				notPresent = append(notPresent, pyjson.O("component", pkg.Name, "version", pkg.Version, "status", st, "cves", list))
			}
		}
	}

	if len(notPresent) > 0 {
		n, open := 0, 0
		for _, x := range notPresent {
			for _, c := range x.(*pyjson.Obj).G("cves").([]any) {
				n++
				if v := c.(*pyjson.Obj).G("sbom_vex"); v != "fixed" && v != "not_affected" {
					open++
				}
			}
		}
		findings = append(findings, model.Finding{Check: "sbom.cves-not-in-image", Severity: "info",
			Title: fmt.Sprintf("%d CVE(s) belong to %d component(s) that are not in the image (%d not already fixed or not_affected in the SBOM)",
				n, len(notPresent), open),
			Detail:   "Candidates for VEX not_affected / component_not_present.",
			Evidence: pyjson.O("components", notPresent)})
	}
	return &Comparison{Status: status, NotPresent: notPresent, Findings: findings}
}

func withID(pid string, c *pyjson.Obj) *pyjson.Obj {
	o := pyjson.O("spdxId", pid)
	for _, k := range c.Keys() {
		o.Set(k, c.G(k))
	}
	return o
}

// Graph builds nodes/edges for the report UI (recipes and binary packages, without sources).
// Nodes follow the SBOM's order (the Python version iterated a set, so its order varied per run).
func Graph(sb *Sbom, status *Status) *pyjson.Obj {
	nodes, edges := []any{}, []any{}
	keep := map[string]bool{}
	for _, pid := range sb.PackageOrder {
		p := sb.Packages[pid]
		if p.Role != "recipe" && p.Role != "package" {
			continue
		}
		keep[pid] = true
		st := "unknown"
		var files any
		if o, ok := status.M[pid]; ok {
			st = o.G("status").(string)
			if f, ok := o.Get("files"); ok {
				files = f
			}
		}
		cves := []any{}
		for _, c := range sb.Vulns.M[pid] {
			cves = append(cves, pyjson.O("id", c, "vex", sb.Vex(c, pid)))
		}
		nodes = append(nodes, pyjson.O("id", pid, "name", p.Name, "version", p.Version, "role", p.Role,
			"purl", p.Purl, "cpes", p.Cpes, "status", st, "files", files, "cves", cves))
	}
	for _, rel := range []struct {
		kind string
		l    *IDList
	}{{"generates", sb.Generates}, {"runtime", sb.RuntimeDeps}, {"build", sb.BuildDeps}} {
		for _, src := range rel.l.Keys {
			for _, d := range rel.l.M[src] {
				if keep[src] && keep[d] {
					edges = append(edges, pyjson.O("source", src, "target", d, "kind", rel.kind))
				}
			}
		}
	}
	return pyjson.O("nodes", nodes, "edges", edges)
}
