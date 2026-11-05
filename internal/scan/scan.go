// Package scan runs every check over an unpacked rootfs and assembles the report.
package scan

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/corefense-security/trowl/internal/checks/elfcheck"
	"github.com/corefense-security/trowl/internal/checks/fstab"
	"github.com/corefense-security/trowl/internal/checks/kconfig"
	"github.com/corefense-security/trowl/internal/checks/secrets"
	"github.com/corefense-security/trowl/internal/feeds"
	"github.com/corefense-security/trowl/internal/llm"
	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/nvd"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/corefense-security/trowl/internal/sbom"
	"github.com/corefense-security/trowl/internal/unpack"
)

type Options struct {
	SBOM         string
	Network      bool
	CacheDir     string
	Links        string // open | all | none
	Model        string // "" disables the model
	KernelConfig string
	KernelSrc    string
	KernelPolicy string
}

type Result struct {
	Report     *pyjson.Obj
	Findings   []model.Finding
	Files      int
	Binaries   int
	Format     string
	Counts     *pyjson.Counter
	SbomCounts *pyjson.Obj // nil without an SBOM
}

func Run(u *unpack.Unpacked, image string, opt Options) (*Result, error) {
	t0 := time.Now()
	rootfs := u.Rootfs
	var findings []model.Finding
	binaries := []any{}
	fileCount := 0

	unpack.IterFiles(rootfs, func(imagePath, real string) {
		fileCount++
		findings = append(findings, secrets.ScanFile(imagePath, real)...)
		if props := elfcheck.Analyse(real); props != nil {
			b := pyjson.O("path", imagePath)
			for _, k := range props.Keys() {
				b.Set(k, props.G(k))
			}
			binaries = append(binaries, b)
			findings = append(findings, elfcheck.FindingsFor(imagePath, props)...)
		}
	})

	fstabEntries, fstabFindings := fstab.Check(rootfs)
	findings = append(findings, fstabFindings...)
	kernelSection, kernelFindings, err := kconfig.Check(rootfs, opt.KernelConfig, opt.KernelSrc, opt.KernelPolicy)
	if err != nil {
		return nil, err
	}
	findings = append(findings, kernelFindings...)

	var sbomSection *pyjson.Obj
	var sb *sbom.Sbom
	if opt.SBOM != "" {
		sb, err = sbom.Load(opt.SBOM)
		if err != nil {
			return nil, err
		}
		cmp := sbom.Compare(sb, rootfs)
		modulePackages(rootfs, kernelSection, sb)
		findings = append(findings, cmp.Findings...)
		roles := pyjson.NewCounter()
		for _, pid := range sb.PackageOrder {
			roles.Add(sb.Packages[pid].Role, 1)
		}
		type rs struct{ role, status string }
		statusN := map[rs]int{}
		for _, pid := range cmp.Status.Keys {
			statusN[rs{sb.Packages[pid].Role, cmp.Status.Of(pid)}]++
		}
		keys := make([]rs, 0, len(statusN))
		for k := range statusN {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].role != keys[j].role {
				return keys[i].role < keys[j].role
			}
			return keys[i].status < keys[j].status
		})
		statusCounts := pyjson.New()
		for _, k := range keys {
			statusCounts.Set(k.role+":"+k.status, statusN[k])
		}
		sbomSection = pyjson.O(
			"file", py.CleanPath(opt.SBOM),
			"name", sb.Name,
			"components", roles,
			"status_counts", statusCounts,
			"not_present", cmp.NotPresent,
			"graph", sbom.Graph(sb, cmp.Status),
			"cves", cveSection(sb, cmp.Status, opt),
		)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := model.SeverityRank(a.Severity), model.SeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Path < b.Path
	})
	bySev, byCheck, elfKinds := pyjson.NewCounter(), pyjson.NewCounter(), pyjson.NewCounter()
	findingObjs := make([]any, len(findings))
	for i, f := range findings {
		bySev.Add(f.Severity, 1)
		byCheck.Add(f.Check, 1)
		findingObjs[i] = f.Obj()
	}
	for _, b := range binaries {
		elfKinds.Add(b.(*pyjson.Obj).G("kind").(string), 1)
	}
	notes := u.Notes
	if notes == nil {
		notes = []string{}
	}
	var sbomOut any
	if sbomSection != nil {
		sbomOut = sbomSection
	}
	result := pyjson.O(
		"tool", pyjson.O("name", "trowl", "version", model.Version),
		"image", pyjson.O("path", py.CleanPath(image), "format", u.SourceFormat, "files", fileCount, "notes", notes),
		"summary", pyjson.O(
			"findings", bySev,
			"by_check", byCheck,
			"elf", elfKinds,
			"duration_s", py.Round2(time.Since(t0).Seconds()),
		),
		"findings", findingObjs,
		"binaries", binaries,
		"fstab", fstabEntries,
		"kernel", kernelSection,
		"sbom", sbomOut,
		"overview", nil,
	)
	if opt.Model != "" && opt.CacheDir != "" {
		runner := llm.NewRunner(opt.Model, opt.CacheDir)
		defer runner.Close()
		if ov := llm.Overview(runner, overviewFacts(result, findingObjs, binaries, kernelSection, sbomSection)); ov != nil {
			result.Set("overview", ov)
		}
	}
	res := &Result{Report: result, Findings: findings, Files: fileCount, Binaries: len(binaries),
		Format: u.SourceFormat, Counts: bySev}
	if sbomSection != nil {
		res.SbomCounts = sbomSection.G("status_counts").(*pyjson.Obj)
	}
	return res, nil
}

func pct(n, d int) string {
	p := 0
	if d != 0 {
		p = py.Round(100 * float64(n) / float64(d))
	}
	return fmt.Sprintf("%d of %d (%d%%)", n, d, p)
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int:
		return x != 0
	case string:
		return x != ""
	}
	return true
}

// overviewFacts are the numbers the Overview page shows, as plain facts for the model to
// summarise. Keys are numbered in the order the summary should cover them, most important first.
func overviewFacts(r *pyjson.Obj, findings []any, binaries []any, kernel, sb *pyjson.Obj) *pyjson.Obj {
	var judged []*pyjson.Obj
	for _, b := range binaries {
		bo := b.(*pyjson.Obj)
		if k := bo.G("kind"); k == "executable" || k == "library" {
			judged = append(judged, bo)
		}
	}
	fortifiable := func(b *pyjson.Obj) bool {
		f, _ := b.G("fortify").(*pyjson.Obj)
		return f != nil && (truthy(f.G("fortified")) || truthy(f.G("unfortified")))
	}
	// The critical protections a binary can lack. Partial RELRO counts as protected; a missing
	// canary counts only where there are buffer calls to protect (as the elf.canary check does);
	// CFI is judged only on architectures whose ELF notes record it (x86 IBT, arm64 BTI).
	lacks := func(b *pyjson.Obj) []string {
		var m []string
		if b.G("pie") == false {
			m = append(m, "PIE")
		}
		if b.G("relro") == "none" {
			m = append(m, "RELRO")
		}
		if !truthy(b.G("canary")) && fortifiable(b) {
			m = append(m, "stack protector")
		}
		cf, _ := b.G("cf_protection").(*pyjson.Obj)
		switch b.G("arch") {
		case "EM_X86_64", "EM_386":
			if !truthy(cf.G("ibt")) {
				m = append(m, "CFI")
			}
		case "EM_AARCH64":
			if !truthy(cf.G("bti")) {
				m = append(m, "CFI")
			}
		}
		return m
	}
	const maxNamed = 3
	var weakBins []*pyjson.Obj
	missing := pyjson.NewCounter()
	for _, k := range []string{"PIE", "RELRO", "stack protector", "CFI"} {
		missing.Add(k, 0)
	}
	for _, b := range judged {
		if m := lacks(b); len(m) > 0 {
			weakBins = append(weakBins, b)
			for _, k := range m {
				missing.Add(k, 1)
			}
		}
	}
	// Name the binaries that lack the most protections first.
	sort.SliceStable(weakBins, func(i, j int) bool { return len(lacks(weakBins[i])) > len(lacks(weakBins[j])) })
	named := []string{}
	for i, b := range weakBins {
		if i == maxNamed {
			break
		}
		named = append(named, fmt.Sprintf("%s (no %s)", path.Base(b.G("path").(string)), strings.Join(lacks(b), "/")))
	}
	facts := pyjson.New()
	if sb != nil {
		if cv, _ := sb.G("cves").(*pyjson.Obj); cv != nil {
			s := cv.G("summary").(*pyjson.Obj)
			var kev any = "not checked"
			if cv.G("sources").(*pyjson.Obj).G("kev") != nil {
				kev = s.G("kev")
			}
			sev := s.G("severity").(*pyjson.Counter)
			status := s.G("status").(*pyjson.Counter)
			comps := []string{}
			for i, c := range s.G("by_component").([]any) {
				if i == 3 {
					break
				}
				co := c.(*pyjson.Obj)
				total := 0
				for _, k := range co.Keys() {
					if k != "name" {
						total += co.G(k).(int)
					}
				}
				comps = append(comps, fmt.Sprintf("%s: %d", co.G("name"), total))
			}
			facts.Set("1. Vulnerabilities", pyjson.O(
				"Unpatched CVEs on packages that ship", s.G("unpatched_shipped"),
				"Unpatched CVEs with CVSS 7.0 or higher", s.G("high"),
				"Unpatched CVEs in the CISA Known Exploited Vulnerabilities list", kev,
				"Unpatched CVEs without a CVSS score", sev.Get("none"),
				"Components with the most unpatched CVEs", comps,
				"CVEs marked fixed in the SBOM", status.Get("fixed"),
			))
		}
	}
	secretsC := pyjson.NewCounter()
	var mountIssues []string
	for _, f := range findings {
		fo := f.(*pyjson.Obj)
		check := fo.G("check").(string)
		if strings.HasPrefix(check, "secrets.") {
			secretsC.Add(fmt.Sprintf("%s: %s", fo.G("severity"), fo.G("title")), 1)
		}
		if check == "fstab.mount-options" {
			mountIssues = append(mountIssues, fo.G("title").(string))
		}
	}
	if kernel != nil && kernel.G("source") != nil {
		var failing []*pyjson.Obj
		checked, accepted := 0, 0
		for _, e := range kernel.G("entries").([]any) {
			eo := e.(*pyjson.Obj)
			switch eo.G("status") {
			case "fail", "missing":
				failing = append(failing, eo)
			case "accepted":
				accepted++
			}
			if eo.G("status") != "na" {
				checked++
			}
		}
		exposed, weak := []string{}, []string{}
		for _, e := range failing {
			if e.G("bucket") == "attack_surface" {
				exposed = append(exposed, e.G("option").(string))
			} else if e.G("bucket") == "harden" {
				weak = append(weak, e.G("option").(string))
			}
		}
		first := weak
		if len(first) > 4 {
			first = first[:4]
		}
		// Counts are given as numbers so the model copies them instead of counting a list.
		facts.Set("2. Kernel", pyjson.O(
			"Kernel", strings.TrimSpace(fmt.Sprintf("Linux %s %s", kernel.G("version"), kernel.G("arch"))),
			"Config options checked", checked,
			"Options failing the baseline", len(failing),
			"Attack-surface options enabled that should be off", len(exposed),
			"Those options", exposed,
			"Hardening options missing that should be on", len(weak),
			"First of those options", first,
			"Accepted by team policy", accepted,
		))
	}
	if mountIssues == nil {
		mountIssues = []string{}
	}
	total := 0
	for _, k := range secretsC.Keys() {
		total += secretsC.Get(k)
	}
	fs := pyjson.O("Insecure mounts (missing a secure flag)", len(mountIssues), "Those mounts", mountIssues,
		"Private keys, host keys or tokens found", total)
	if total > 0 {
		var kinds []string
		for _, k := range secretsC.MostCommon() {
			kinds = append(kinds, fmt.Sprintf("%d x %s", secretsC.Get(k), k))
		}
		fs.Set("Secrets by kind", kinds)
	}
	facts.Set("3. Filesystems", fs)
	missingIn := func(k string) string { return fmt.Sprintf("%d of %d", missing.Get(k), len(judged)) }
	facts.Set("4. Hardening", pyjson.O(
		"Executables and libraries checked", len(judged),
		"Lacking at least one critical protection", pct(len(weakBins), len(judged)),
		"Without PIE", missingIn("PIE"),
		"Without RELRO", missingIn("RELRO"),
		"Without stack overflow protection", missingIn("stack protector"),
		"Without CFI protection", missingIn("CFI"),
		"Examples", strings.Join(named, ", "),
		"Others not named", max(len(weakBins)-len(named), 0),
	))
	if sb != nil {
		sc := sb.G("status_counts").(*pyjson.Obj)
		n := func(k string) int {
			v, _ := sc.G(k).(int)
			return v
		}
		facts.Set("5. SBOM", pyjson.O(
			"Packages in the image", n("package:present")+n("package:modified"),
			"Packages whose files differ from the SBOM", n("package:modified"),
			"Packages listed in the SBOM but missing from the image", n("package:absent")+n("package:partial"),
			"Source components used only at build time (not shipped)", n("recipe:build-only"),
		))
	}
	return facts
}

func cveSection(sb *sbom.Sbom, status *sbom.Status, opt Options) *pyjson.Obj {
	matched := versionMatch(sb, opt)
	rows := sbom.BuildCVEs(sb, status)
	sources := pyjson.O("kev", nil, "epss", nil, "links", "none", "version_match", matched)
	if opt.Network && opt.CacheDir != "" {
		kev, kevMeta := feeds.KEV(opt.CacheDir)
		wanted := map[string]bool{}
		for _, r := range rows {
			wanted[r.G("id").(string)] = true
		}
		scores, epssMeta := feeds.EPSS(opt.CacheDir, wanted)
		sources.Set("kev", nilIfNone(kevMeta))
		sources.Set("epss", nilIfNone(epssMeta))
		for _, r := range rows {
			id := r.G("id").(string)
			r.Set("kev", nilIfNone(kev[id]))
			r.Set("epss", nilIfNone(scores[id]))
		}
		if opt.Links != "none" {
			var scope []string
			kernel := map[string]bool{}
			for _, r := range rows {
				id := r.G("id").(string)
				if opt.Links == "all" || r.G("status") != "fixed" {
					scope = append(scope, id)
				}
				if r.G("kernel") == true {
					kernel[id] = true
				}
			}
			found := feeds.CheckLinks(opt.CacheDir, scope, kernel)
			for _, r := range rows {
				if l, ok := found[r.G("id").(string)]; ok {
					r.Set("links", l)
				} else {
					r.Set("links", nil)
				}
			}
			sources.Set("links", opt.Links)
		}
	}
	rowsOut := make([]any, len(rows))
	for i, r := range rows {
		rowsOut[i] = r
	}
	return pyjson.O("summary", sbom.Summary(rows), "sources", sources, "rows", rowsOut)
}

func nilIfNone(o *pyjson.Obj) any {
	if o == nil {
		return nil
	}
	return o
}

// modulePackages names the SBOM package that ships each kernel module, from the packages' file lists.
func modulePackages(rootfs string, kernel *pyjson.Obj, sb *sbom.Sbom) {
	if kernel == nil {
		return
	}
	mods, _ := kernel.G("modules").(*pyjson.Obj)
	if mods == nil {
		return
	}
	items, _ := mods.G("items").([]any)
	if len(items) == 0 {
		return
	}
	// The SBOM links a package to a module only through the file path it declares, so the join
	// is by path. Two things make a naive lookup unreliable:
	//   - the spelling need not match the one the scan used: on a merged-/usr image the SBOM
	//     names the module /usr/lib/... while the scan read it through the /lib symlink. Both
	//     name the same file, so each side is resolved against the image before comparing.
	//   - a file is usually declared by two packages, its own and the image's, which lists
	//     every file in the image. The one declaring fewest files is the specific owner.
	real := func(path string) string {
		r := py.Resolve(filepath.Join(rootfs, strings.TrimLeft(path, "/")))
		if rel, err := filepath.Rel(rootfs, r); err == nil {
			return "/" + rel
		}
		return path
	}
	owner := map[string]*sbom.Package{}
	for _, pid := range sb.PackageOrder {
		p := sb.Packages[pid]
		if p.Role != "package" {
			continue
		}
		for _, f := range p.Files {
			if !hasModuleSuffix(f.Name) {
				continue
			}
			key := real(f.Name)
			if cur := owner[key]; cur == nil || len(p.Files) < len(cur.Files) {
				owner[key] = p
			}
		}
	}
	for _, m := range items {
		mo := m.(*pyjson.Obj)
		name := ""
		if p := owner[real(mo.G("path").(string))]; p != nil {
			name = p.Name
		}
		mo.Set("package", name)
	}
}

// hasModuleSuffix reports whether a file name is a kernel module, compressed or not.
func hasModuleSuffix(name string) bool {
	for _, s := range []string{".ko", ".ko.gz", ".ko.xz", ".ko.zst"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func warn(format string, a ...any) { fmt.Fprintf(os.Stderr, "trowl: "+format+"\n", a...) }

// versionMatch adds the CVEs that NVD and the kernel CNA list for each component's version,
// as Trivy and Grype do. The SBOM's own VEX statuses are kept. It returns the data's
// provenance for the report, or nil when nothing was matched.
func versionMatch(sb *sbom.Sbom, opt Options) any {
	if opt.CacheDir == "" {
		return nil
	}
	cpes := sb.MatchTargets()
	if len(cpes) == 0 {
		return nil
	}
	targets := make([]nvd.Target, len(cpes))
	for i, c := range cpes {
		targets[i] = nvd.Target{Comp: c.Comp, Vendor: c.Vendor, Product: c.Product, Version: c.Version}
	}
	t0 := time.Now()
	res := nvd.Run(opt.CacheDir, opt.Network, targets)
	if res == nil {
		return nil
	}
	for _, m := range res.Matches {
		var vi *sbom.VulnInfo
		if in := res.Info[m.CVE]; in != nil {
			vi = &sbom.VulnInfo{Description: in.Description, Published: in.Published,
				CVSS: map[string]*sbom.CVSS{}, CVSSOrder: in.CVSSOrder}
			for k, c := range in.CVSS {
				vi.CVSS[k] = &sbom.CVSS{Score: c.Score, Vector: c.Vector, Severity: c.Severity}
			}
		}
		sb.AddMatch(m.Comp, m.CVE, vi)
	}
	warn("version match: %d CVE match(es) for %d component CPE(s) in %.1fs", len(res.Matches), len(cpes),
		time.Since(t0).Seconds())
	meta := pyjson.New()
	for _, k := range []string{"source", "updated", "years"} {
		meta.Set(k, res.Meta[k])
	}
	meta.Set("matches", len(res.Matches))
	return meta
}
