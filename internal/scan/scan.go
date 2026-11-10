// Package scan runs every check over an unpacked rootfs and assembles the report.
package scan

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/corefense-security/trowl/internal/checks/elfcheck"
	"github.com/corefense-security/trowl/internal/checks/fstab"
	"github.com/corefense-security/trowl/internal/checks/kconfig"
	"github.com/corefense-security/trowl/internal/checks/secrets"
	"github.com/corefense-security/trowl/internal/feeds"
	"github.com/corefense-security/trowl/internal/inventory"
	"github.com/corefense-security/trowl/internal/llm"
	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/nvd"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/corefense-security/trowl/internal/sbom"
	"github.com/corefense-security/trowl/internal/status"
	"github.com/corefense-security/trowl/internal/unpack"
	"github.com/corefense-security/trowl/internal/vex"
)

type Options struct {
	SBOM         string
	Network      bool
	CacheDir     string
	Links        string // open | all | none
	Model        string // "" disables the model
	KernelConfig string
	KernelSrc    string
	KernelTree   string // source tree of the image's kernel, for the VEX of kernel CVEs
	KernelPolicy string
	Started      time.Time // when the scan began, including unpacking; zero means when Run was called
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
	started := opt.Started
	if started.IsZero() {
		started = time.Now()
	}
	rootfs := u.Rootfs
	var findings []model.Finding
	binaries := []any{}
	fileCount, secretCount := 0, 0

	st := status.Start("trowling binaries")
	unpack.IterFiles(rootfs, func(imagePath, real string) {
		fileCount++
		found := secrets.ScanFile(imagePath, real)
		secretCount += len(found)
		findings = append(findings, found...)
		if props := elfcheck.Analyse(real); props != nil {
			b := pyjson.O("path", imagePath)
			for _, k := range props.Keys() {
				b.Set(k, props.G(k))
			}
			if p, ok := u.Perms[imagePath]; ok {
				b.Set("mode", p.Mode)
				b.Set("uid", p.UID)
				b.Set("gid", p.GID)
			}
			binaries = append(binaries, b)
			findings = append(findings, elfcheck.FindingsFor(imagePath, props)...)
		}
	})
	if fileCount == 0 {
		st.Fail("")
		return nil, fmt.Errorf("no files found in %s; the image may be corrupt", py.CleanPath(image))
	}
	walked := fmt.Sprintf("%d files, %d ELF, %d secret(s)", fileCount, len(binaries), secretCount)
	if len(binaries) == 0 {
		st.Fail(walked)
	} else {
		st.Ok(walked)
	}

	st = status.Start("checking mounts")
	fstabEntries, fstabFindings := fstab.Check(rootfs)
	findings = append(findings, fstabFindings...)
	if len(fstabFindings) > 0 && fstabFindings[0].Check == "fstab.missing" {
		st.Fail("no /etc/fstab")
	} else {
		st.Ok(fmt.Sprintf("%d in fstab", len(fstabEntries)))
	}

	st = status.Start("digging up kernel config")
	kernelSection, kernelFindings, err := kconfig.Check(rootfs, opt.KernelConfig, opt.KernelSrc, opt.KernelPolicy)
	if err != nil {
		st.Fail("")
		return nil, err
	}
	findings = append(findings, kernelFindings...)
	if source, _ := kernelSection.G("source").(*pyjson.Obj); source != nil {
		st.Ok(fmt.Sprint(source.G("path")))
	} else {
		st.Fail("not found")
	}

	var sbomSection, cves *pyjson.Obj
	var sb *sbom.Sbom
	if opt.SBOM != "" {
		st = status.Start("reading SBOM")
		sb, err = sbom.Load(opt.SBOM)
		if err != nil {
			st.Fail("")
			return nil, err
		}
		if len(sb.PackageOrder) == 0 {
			st.Fail("")
			return nil, fmt.Errorf("%s lists no components", py.CleanPath(opt.SBOM))
		}
		st.Ok(fmt.Sprintf("%d components", len(sb.PackageOrder)))
		st = status.Start("matching SBOM to image")
		if err := checkKernelVersion(sb, kconfig.ModulesVersion(rootfs)); err != nil {
			st.Fail("")
			return nil, err
		}
		cmp := sbom.Compare(sb, rootfs, u.OtherPartitions)
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
		// Counted as the Overview counts them: a package with no files can't be seen either way.
		shipped := statusN[rs{"package", "present"}] + statusN[rs{"package", "modified"}] + statusN[rs{"package", "partial"}]
		inImage := fmt.Sprintf("%d of %d packages in image", shipped, shipped+statusN[rs{"package", "absent"}])
		if shipped == 0 {
			st.Fail(inImage)
		} else {
			st.Ok(inImage)
		}
		sbomSection = pyjson.O(
			"file", py.CleanPath(opt.SBOM),
			"name", sb.Name,
			"components", roles,
			"status_counts", statusCounts,
			"not_present", cmp.NotPresent,
			"graph", sbom.Graph(sb, cmp.Status),
		)
		cves, err = cveSection(sb, cmp.Status, rootfs, opt)
	} else if inv, presence := imageInventory(rootfs, kernelVersion(kernelSection)); inv != nil {
		cves, err = cveSection(inv, presence, rootfs, opt)
	}
	if err != nil {
		return nil, err
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
	var sbomOut, cvesOut any
	if sbomSection != nil {
		sbomOut = sbomSection
	}
	if cves != nil {
		cvesOut = cves
	}
	result := pyjson.O(
		"tool", pyjson.O("name", "trowl", "version", model.Version),
		"image", pyjson.O("path", py.CleanPath(image), "format", u.SourceFormat, "files", fileCount, "notes", notes),
		"summary", pyjson.O(
			"findings", bySev,
			"by_check", byCheck,
			"elf", elfKinds,
			"scanned_at", started.UTC().Format(time.RFC3339),
			"duration_s", nil,
		),
		"findings", findingObjs,
		"binaries", binaries,
		"fstab", fstabEntries,
		"kernel", kernelSection,
		"sbom", sbomOut,
		"cves", cvesOut,
		"overview", nil,
	)
	if opt.Model != "" && opt.CacheDir != "" {
		st = status.Start("writing overview")
		runner := llm.NewRunner(opt.Model, opt.CacheDir)
		defer runner.Close()
		if ov := llm.Overview(runner, overviewFacts(findingObjs, binaries, kernelSection, sbomSection, cves)); ov != nil {
			result.Set("overview", ov)
			st.Ok(llm.Models[opt.Model].Label)
		} else {
			st.Fail("no model output")
		}
	}
	result.G("summary").(*pyjson.Obj).Set("duration_s", py.Round2(time.Since(started).Seconds()))
	res := &Result{Report: result, Findings: findings, Files: fileCount, Binaries: len(binaries),
		Format: u.SourceFormat, Counts: bySev}
	if sbomSection != nil {
		res.SbomCounts = sbomSection.G("status_counts").(*pyjson.Obj)
	}
	return res, nil
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

// overviewFacts are the facts the model interprets for the Overview summary. Every number is
// computed here; the model only explains them. Keys are numbered in the order to cover them.
func overviewFacts(findings []any, binaries []any, kernel, sb, cv *pyjson.Obj) *pyjson.Obj {
	facts := pyjson.New()
	sv := pyjson.New()
	if sb != nil {
		sc := sb.G("status_counts").(*pyjson.Obj)
		n := func(k string) int {
			v, _ := sc.G(k).(int)
			return v
		}
		shipped := n("package:present") + n("package:modified") + n("package:partial")
		sv.Set("Packages in the SBOM", shipped+n("package:absent"))
		sv.Set("Packages shipped", shipped)
		sv.Set("SBOM packages not installed", n("package:absent"))
		sv.Set("Packages changed after build", n("package:modified"))
		sv.Set("Packages with files missing", n("package:partial"))
	}
	if cv != nil {
		cveFacts(sv, cv, sb != nil)
	}
	if sv.Len() > 0 {
		facts.Set("1. SBOM and vulnerabilities", sv)
	}
	if kernel != nil && kernel.G("source") != nil {
		exposed, weak := pyjson.New(), pyjson.New()
		for _, e := range kernel.G("entries").([]any) {
			eo := e.(*pyjson.Obj)
			if s := eo.G("status"); s != "fail" && s != "missing" {
				continue
			}
			option := eo.G("option").(string)
			fact := pyjson.O("Why", eo.G("why"), "Fix", kernelFix(option, eo.G("expect")))
			if eo.G("bucket") == "attack_surface" {
				exposed.Set(option, fact)
			} else if eo.G("bucket") == "harden" {
				weak.Set(option, fact)
			}
		}
		facts.Set("2. Kernel", pyjson.O(
			"Kernel", strings.TrimSpace(fmt.Sprintf("Linux %s %s", kernel.G("version"), kernel.G("arch"))),
			"Attack-surface options enabled that should be off", exposed,
			"Hardening options missing that should be on", weak,
		))
	}
	mountIssues := []string{}
	var secretPaths []string
	for _, f := range findings {
		fo := f.(*pyjson.Obj)
		check := fo.G("check").(string)
		if strings.HasPrefix(check, "secrets.") {
			secretPaths = append(secretPaths, fo.G("path").(string))
		}
		if check == "fstab.mount-options" {
			mountIssues = append(mountIssues, fo.G("title").(string))
		}
	}
	facts.Set("3. Filesystems", pyjson.O("Insecure mounts (missing a secure flag)", len(mountIssues), "Those mounts", mountIssues,
		"Secrets found per directory", secretDirs(secretPaths, maxSecretDirs)))
	facts.Set("4. Hardening", hardeningFacts(binaries))
	return facts
}

// kernelFix is the setting that clears a failing option, such as CONFIG_PROC_KCORE=n.
func kernelFix(option string, expect any) string {
	if o, ok := expect.(*pyjson.Obj); ok {
		if m := o.G("min"); m != nil {
			return fmt.Sprintf("CONFIG_%s=%v", option, m)
		}
		return fmt.Sprintf("CONFIG_%s: %s", option, pyjson.Compact(o))
	}
	return fmt.Sprintf("CONFIG_%s=%v", option, expect)
}

// hardeningFacts counts the executables and libraries missing each flag. A stripped static
// binary has no symbols to judge its canary or FORTIFY by, so it isn't counted for those.
func hardeningFacts(binaries []any) *pyjson.Obj {
	missing := pyjson.NewCounter()
	for _, k := range []string{"PIE", "NX", "RELRO", "partial RELRO", "stack canary", "FORTIFY"} {
		missing.Add(k, 0)
	}
	checked, cfChecked := 0, 0
	for _, b := range binaries {
		bo := b.(*pyjson.Obj)
		kind := bo.G("kind")
		if kind != "executable" && kind != "library" {
			continue
		}
		checked++
		if kind == "executable" && bo.G("pie") == false {
			missing.Add("PIE", 1)
		}
		if !truthy(bo.G("nx")) {
			missing.Add("NX", 1)
		}
		switch bo.G("relro") {
		case "none":
			missing.Add("RELRO", 1)
		case "partial":
			missing.Add("partial RELRO", 1)
		}
		if !truthy(bo.G("no_symbols")) {
			if !truthy(bo.G("canary")) {
				missing.Add("stack canary", 1)
			}
			if f, _ := bo.G("fortify").(*pyjson.Obj); f == nil || !truthy(f.G("fortified")) {
				missing.Add("FORTIFY", 1)
			}
		}
		// Only x86 and arm64 ELF notes record these; other architectures have no cf_protection.
		if cf, _ := bo.G("cf_protection").(*pyjson.Obj); cf != nil {
			cfChecked++
			if !truthy(cf.G("ibt")) && !truthy(cf.G("bti")) {
				missing.Add("CFI", 1)
			}
			if !truthy(cf.G("shstk")) && !truthy(cf.G("pac")) {
				missing.Add("shadow stack or PAC", 1)
			}
		}
	}
	out := pyjson.O(
		"Executables and libraries checked", checked,
		"Note", "A binary can miss several flags, so these numbers overlap and must not be added.",
		"Executables without PIE", missing.Get("PIE"),
		"Without NX", missing.Get("NX"),
		"Without RELRO", missing.Get("RELRO"),
		"With only partial RELRO", missing.Get("partial RELRO"),
		"Without a stack canary", missing.Get("stack canary"),
		"Without FORTIFY", missing.Get("FORTIFY"),
	)
	if cfChecked > 0 {
		out.Set("Without CFI", missing.Get("CFI"))
		out.Set("Without a shadow stack or PAC", missing.Get("shadow stack or PAC"))
	}
	return out
}

// topCVE names the highest-CVSS unpatched CVE on a shipped package, with its component; userland
// leaves out kernel CVEs. Equal scores go to the lowest id, so the fact is the same every run.
func topCVE(rows []any, userland bool) string {
	var best *pyjson.Obj
	top := -1.0
	for _, x := range rows {
		row := x.(*pyjson.Obj)
		cvss, _ := row.G("cvss").(*pyjson.Obj)
		if cvss == nil || !openShipped(row) || (userland && truthy(row.G("kernel"))) {
			continue
		}
		score, _ := cvss.G("score").(float64)
		if score > top || (score == top && row.G("id").(string) < best.G("id").(string)) {
			best, top = row, score
		}
	}
	if best == nil {
		return "none"
	}
	return fmt.Sprintf("%s (CVSS %.1f, %s)", best.G("id"), top, openCarrier(best))
}

func openShipped(row *pyjson.Obj) bool {
	return row.G("status") == "unpatched" && sbom.MayShip(row.G("shipped").(string))
}

// openCarrier is the first shipped package that leaves the CVE unpatched.
func openCarrier(row *pyjson.Obj) string {
	for _, c := range row.G("carriers").([]any) {
		if co := c.(*pyjson.Obj); sbom.MayShip(co.G("shipped").(string)) && co.G("status") == "unpatched" {
			return co.G("name").(string)
		}
	}
	return ""
}

// hasBackport reports whether a carrier has the fix in its own stable series.
func hasBackport(row *pyjson.Obj) bool {
	for _, c := range row.G("carriers").([]any) {
		if truthy(c.(*pyjson.Obj).G("backport")) {
			return true
		}
	}
	return false
}

// topEPSS is the shipped, unpatched CVE most likely to be exploited soon, by EPSS score.
func topEPSS(rows []any) string {
	var best *pyjson.Obj
	top := -1.0
	for _, x := range rows {
		row := x.(*pyjson.Obj)
		epss, _ := row.G("epss").(*pyjson.Obj)
		if epss == nil || !openShipped(row) {
			continue
		}
		score, _ := epss.G("score").(float64)
		if score > top || (score == top && row.G("id").(string) < best.G("id").(string)) {
			best, top = row, score
		}
	}
	if best == nil {
		return "none"
	}
	return fmt.Sprintf("%s (EPSS %.2f, %s)", best.G("id"), top, openCarrier(best))
}

// topPackages lists the packages with the most critical, then high, unpatched CVEs.
func topPackages(components []any, limit int) []any {
	count := func(o *pyjson.Obj, k string) int {
		v, _ := o.G(k).(int)
		return v
	}
	ranked := []*pyjson.Obj{}
	for _, c := range components {
		if o := c.(*pyjson.Obj); count(o, "critical")+count(o, "high") > 0 {
			ranked = append(ranked, o)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if count(a, "critical") != count(b, "critical") {
			return count(a, "critical") > count(b, "critical")
		}
		return count(a, "high") > count(b, "high")
	})
	out := []any{}
	for _, o := range ranked[:min(limit, len(ranked))] {
		out = append(out, fmt.Sprintf("%s: %d critical, %d high", o.G("name"), count(o, "critical"), count(o, "high")))
	}
	return out
}

// cveFacts adds the CVE triage facts. Only shipped, unpatched CVEs count.
func cveFacts(sv, cv *pyjson.Obj, hasSBOM bool) {
	sources := cv.G("sources").(*pyjson.Obj)
	summary := cv.G("summary").(*pyjson.Obj)
	rows := cv.G("rows").([]any)
	if !hasSBOM {
		inventory := "the image's package database"
		if s, ok := sources.G("inventory").(string); ok && s != "" {
			inventory = "the image's " + s + " database"
		}
		sv.Set("SBOM", "Not supplied; package versions came from "+inventory)
	}
	found := "Matched by package version; not confirmed as exploitable on this image"
	if !hasSBOM {
		found += ". Backported fixes can't be seen without an SBOM, so some may already be fixed"
	}
	sv.Set("How CVEs were found", found)
	if unmapped, _ := cv.G("unmapped").([]any); len(unmapped) > 0 {
		sv.Set("Packages not checked for CVEs (no CVE product mapping)", len(unmapped))
	}
	severity, _ := summary.G("severity").(*pyjson.Obj)
	bySeverity := pyjson.New()
	for _, k := range []string{"critical", "high", "medium", "low"} {
		if severity != nil && severity.G(k) != nil {
			bySeverity.Set(k, severity.G(k))
		}
	}
	if severity != nil && severity.G("none") != nil {
		bySeverity.Set("no CVSS score yet", severity.G("none"))
	}
	sv.Set("Unpatched CVEs by severity", bySeverity)
	kernelHigh, userHigh, networkHigh := 0, 0, 0
	kernelTotal, kernelBackport := 0, 0
	kernelNames := map[string]bool{}
	kevRows := []any{}
	for _, x := range rows {
		row := x.(*pyjson.Obj)
		if !openShipped(row) {
			continue
		}
		if truthy(row.G("kernel")) {
			kernelNames[openCarrier(row)] = true
			kernelTotal++
			if hasBackport(row) {
				kernelBackport++
			}
		}
		if row.G("kev") != nil {
			kevRows = append(kevRows, fmt.Sprintf("%s (%s)", row.G("id"), openCarrier(row)))
		}
		if sev := row.G("severity"); sev != "critical" && sev != "high" {
			continue
		}
		if truthy(row.G("kernel")) {
			kernelHigh++
		} else {
			userHigh++
		}
		if row.G("vector") == "network" {
			networkHigh++
		}
	}
	if kernelTotal > 0 {
		sv.Set("Unpatched kernel CVEs", kernelTotal)
		sv.Set("Unpatched kernel CVEs with a backport for this kernel's stable series", kernelBackport)
	}
	sv.Set("Critical or high unpatched CVEs in the kernel", kernelHigh)
	sv.Set("Critical or high unpatched CVEs in userland", userHigh)
	sv.Set("Critical or high unpatched CVEs with a network attack vector", networkHigh)
	if components, _ := summary.G("by_component").([]any); len(components) > 0 {
		sv.Set("Packages with the most critical and high unpatched CVEs", topPackages(components, 5))
		userland := []any{}
		for _, c := range components {
			if !kernelNames[c.(*pyjson.Obj).G("name").(string)] {
				userland = append(userland, c)
			}
		}
		if top := topPackages(userland, 1); len(top) > 0 {
			sv.Set("Userland package most affected", top[0])
		}
	}
	if sources.G("kev") == nil {
		sv.Set("Unpatched CVEs in the CISA Known Exploited Vulnerabilities list", "not checked")
	} else if len(kevRows) == 0 {
		sv.Set("Unpatched CVEs in the CISA Known Exploited Vulnerabilities list", "none")
	} else {
		sv.Set("Unpatched CVEs in the CISA Known Exploited Vulnerabilities list", kevRows[:min(10, len(kevRows))])
	}
	sv.Set("Highest-CVSS unpatched CVE", topCVE(rows, false))
	sv.Set("Highest-CVSS unpatched userland CVE", topCVE(rows, true))
	if sources.G("epss") != nil {
		sv.Set("Highest-EPSS unpatched CVE", topEPSS(rows))
	}
	if n, _ := summary.G("unpatched_not_shipped").(int); n > 0 {
		sv.Set("Unpatched CVEs on packages that don't ship", n)
	}
}

const maxSecretDirs = 40

// secretDirs counts the secrets per directory, so the model can tell test fixtures from real
// material by path. Past limit it keeps the shallowest directories: real config sits near the
// root, and deep test trees must not push it out.
func secretDirs(paths []string, limit int) *pyjson.Obj {
	counts := map[string]int{}
	for _, p := range paths {
		counts[path.Dir(p)]++
	}
	dirs := make([]string, 0, len(counts))
	for d := range counts {
		dirs = append(dirs, d)
	}
	sort.Slice(dirs, func(i, j int) bool {
		di, dj := strings.Count(dirs[i], "/"), strings.Count(dirs[j], "/")
		if di != dj {
			return di < dj
		}
		return dirs[i] < dirs[j]
	})
	out := pyjson.New()
	for i, d := range dirs {
		if i == limit {
			out.Set("Other directories", len(dirs)-limit)
			break
		}
		out.Set(d, counts[d])
	}
	return out
}

var kernelRelease = regexp.MustCompile(`^\d+(\.\d+)*`)

// checkKernelVersion stops the scan when the SBOM's kernel isn't the one in /lib/modules: the
// SBOM then describes a different build, and every CVE from it would be for the wrong kernel.
func checkKernelVersion(sb *sbom.Sbom, modules string) error {
	if modules == "" {
		return nil
	}
	versions := map[string]bool{}
	for _, id := range sb.PackageOrder {
		for _, c := range sb.Packages[id].Cpes {
			if f := strings.Split(c, ":"); len(f) > 5 && f[4] == "linux_kernel" {
				// Compare release numbers only: a CPE may carry a suffix such as 6.6.0+git.
				if v := kernelRelease.FindString(f[5]); v != "" {
					versions[v] = true
				}
			}
		}
	}
	if len(versions) == 0 || versions[modules] {
		return nil
	}
	listed := make([]string, 0, len(versions))
	for v := range versions {
		listed = append(listed, v)
	}
	sort.Strings(listed)
	return fmt.Errorf("kernel version mismatch: the SBOM lists %s but /lib/modules has %s", strings.Join(listed, ", "), modules)
}

// kernelVersion is the version the kernel check found: from the kernel config's header, else
// from /lib/modules.
func kernelVersion(kernel *pyjson.Obj) string {
	v, _ := kernel.G("version").(string)
	return v
}

// imageInventory builds the component list for CVE matching without an SBOM: the kernel at the
// version given, the rest from the image's package database. It is nil when it finds nothing.
func imageInventory(rootfs, kernel string) (*sbom.Sbom, *sbom.Status) {
	st := status.Start("reading package database")
	var comps []sbom.Package
	addKernel := func(v string) {
		comps = append(comps, sbom.Package{Name: "linux", Version: v,
			Cpes: []string{"cpe:2.3:o:linux:linux_kernel:" + v + ":*:*:*:*:*:*:*"}})
	}
	if kernel != "" {
		addKernel(kernel)
	}
	found, source := inventory.Read(rootfs)
	for _, c := range found {
		if !strings.HasPrefix(c.Name, "linux-yocto") && c.Name != "linux" && c.Name != "kernel" {
			comps = append(comps, sbom.Package{Name: c.Name, Version: c.Version})
			continue
		}
		// The package's version is the last resort, for an image with no config or modules.
		if v := kernelRelease.FindString(c.Version); kernel == "" && v != "" {
			kernel = v
			addKernel(v)
		}
	}
	if len(comps) == 0 {
		st.Fail("not found, and no kernel modules; CVEs not checked")
		return nil, nil
	}
	if source == "" {
		st.Fail("not found; only the kernel is checked for CVEs")
		source = "kernel only"
	} else {
		st.Ok(fmt.Sprintf("%s, %d packages", source, len(found)))
	}
	return sbom.FromInventory(source, comps)
}

func cveSection(sb *sbom.Sbom, presence *sbom.Status, rootfs string, opt Options) (*pyjson.Obj, error) {
	matched, known, inFeed, feed := versionMatch(sb, opt)
	kernelVex, err := assessKernel(sb, feed, rootfs, opt)
	if err != nil {
		return nil, err
	}
	rows := sbom.BuildCVEs(sb, presence)
	sources := pyjson.O("kev", nil, "epss", nil, "links", "none", "version_match", matched, "kernel_vex", kernelVex)
	if opt.Network && opt.CacheDir != "" {
		st := status.Start("fetching KEV")
		kev, kevMeta := feeds.KEV(opt.CacheDir)
		if kevMeta != nil {
			st.Ok(fmt.Sprintf("%d entries", len(kev)))
		} else {
			st.Fail("unavailable")
		}
		wanted := map[string]bool{}
		for _, r := range rows {
			wanted[r.G("id").(string)] = true
		}
		st = status.Start("fetching EPSS")
		scores, epssMeta := feeds.EPSS(opt.CacheDir, wanted)
		if epssMeta != nil {
			st.Ok(fmt.Sprintf("%d of %d CVEs scored", len(scores), len(wanted)))
		} else {
			st.Fail("unavailable")
		}
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
			found := feeds.CheckLinks(opt.CacheDir, scope, kernel, inFeed)
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
	out := pyjson.O("summary", sbom.Summary(rows), "sources", sources, "rows", rowsOut)
	if sb.Inventory != "" {
		sources.Set("inventory", sb.Inventory)
		// A component NVD has no product for can't be checked: its CVEs, if any, are filed under
		// another name. Only known once the feed has been read.
		unmapped := []any{}
		for _, id := range sb.PackageOrder {
			p := sb.Packages[id]
			if product := strings.ToLower(p.Name); known != nil && !known[product] && p.Name != "linux" {
				unmapped = append(unmapped, pyjson.O("name", p.Name, "version", p.Version))
			}
		}
		out.Set("unmapped", unmapped)
	}
	return out, nil
}

// assessKernel sets the VEX status of the kernel's CVEs from the config gates of the files their
// CNA records name. The result is for the report's sources: what was read and what it decided, nil
// when nothing ran. A tree that can't be used stops the scan: asked for, it would otherwise leave
// the report looking as if it had been checked.
func assessKernel(sb *sbom.Sbom, feed *nvd.Result, rootfs string, opt Options) (any, error) {
	if len(sb.KernelComponents()) == 0 {
		return nil, nil
	}
	if opt.KernelTree == "" {
		status.Warn("kernel CVEs stay version matches: pass --kernel-tree to check their config gates")
		return nil, nil
	}
	if feed == nil {
		status.Warn("no CVE data, so --kernel-tree has no CVE records to check")
		return nil, nil
	}
	st := status.Start("checking kernel config gates")
	text, source := kconfig.FindConfig(rootfs, opt.KernelConfig, opt.KernelSrc)
	if source == nil {
		st.Fail("")
		return nil, fmt.Errorf("--kernel-tree needs the kernel's config, and the image has none: pass --kernel-config")
	}
	ev, err := vex.NewKernel(opt.KernelTree, []byte(text))
	if err != nil {
		st.Fail("")
		return nil, err
	}
	for _, comp := range sb.KernelComponents() {
		// The release of the tree must be the kernel's: the gates of another release can clear
		// CVEs this one has.
		if v := kernelRelease.FindString(sb.Packages[comp].Version); v != "" && v != ev.Version() {
			st.Fail("")
			return nil, fmt.Errorf("kernel version mismatch: the tree is %s but the image's kernel is %s", ev.Version(), v)
		}
	}
	// Code the config compiles only into modules is in the image only if the module is.
	modules := vex.ReadModules(rootfs, ev.Version())
	if modules == nil {
		status.Warn(fmt.Sprintf("no single /lib/modules/%s* in the image: code compiled only into modules counts as shipped", ev.Version()))
	}
	ev.SetModules(modules)
	inRange := map[[2]string]bool{}
	for _, m := range feed.Matches {
		inRange[[2]string{m.Comp, m.CVE}] = true
	}
	n := vex.Apply(sb, ev, feed.ProgramFiles, inRange)
	var modulesDir any
	if modules != nil {
		modulesDir = modules.Dir
	}
	st.Ok(fmt.Sprintf("%d not affected, %d affected, %d undecided, %d without files", n.NotAffected, n.Affected, n.Undecided, n.NoFiles))
	return pyjson.O("tree", py.CleanPath(opt.KernelTree), "version", ev.Version(), "build", ev.Build(), "config", source,
		"modules", modulesDir,
		"sbom_assessed", sb.AssessesKernel(), "not_affected", n.NotAffected, "affected", n.Affected, "undecided", n.Undecided,
		"no_files", n.NoFiles, "defies_sbom", n.Defies), nil
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
		r := py.InRoot(rootfs, path)
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

// versionMatch adds the CVEs that NVD and the kernel CNA list for each component's version,
// as Trivy and Grype do. The SBOM's own VEX statuses are kept. It returns the data's
// provenance for the report, the products the feed knows and the CVEs it has records for, or
// nil when nothing was matched. feed is the match itself, nil the same way.
func versionMatch(sb *sbom.Sbom, opt Options) (meta any, known, inFeed map[string]bool, feed *nvd.Result) {
	if opt.CacheDir == "" {
		return nil, nil, nil, nil
	}
	st := status.Start("sifting CVEs")
	cpes := sb.MatchTargets()
	if len(cpes) == 0 {
		st.Fail("no components with a CPE")
		return nil, nil, nil, nil
	}
	targets := make([]nvd.Target, len(cpes))
	for i, c := range cpes {
		targets[i] = nvd.Target{Comp: c.Comp, Vendor: c.Vendor, Product: c.Product, Version: c.Version}
	}
	listed := map[nvd.Match]string{}
	for _, p := range sb.Listed() {
		listed[nvd.Match{Comp: p[0], CVE: p[1]}] = sb.StatedFix(p[1], p[0])
	}
	res := nvd.Run(opt.CacheDir, opt.Network, targets, listed)
	if res == nil {
		st.Fail("no NVD data available")
		return nil, nil, nil, nil
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
		// Without an SBOM no package has a vendor, so saying so of each match would say nothing.
		if !res.Vendored[m] && sb.Inventory == "" {
			sb.MarkNameOnly(m.Comp, m.CVE)
		}
	}
	for m, fix := range res.Fixes {
		sb.SetFix(m.Comp, m.CVE, sbom.Fix(fix))
	}
	st.Ok(fmt.Sprintf("%d match(es) for %d component CPE(s)", len(res.Matches), len(cpes)))
	m := pyjson.New()
	for _, k := range []string{"source", "updated", "years"} {
		m.Set(k, res.Meta[k])
	}
	m.Set("matches", len(res.Matches))
	return m, res.Known, res.InFeed, res
}
