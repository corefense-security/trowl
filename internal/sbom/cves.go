package sbom

// One row per CVE the SBOM attaches to a component, for the dashboard's CVE page.
//
// The status comes from the SBOM's own VEX assessments (Yocto's cve-check / sbom-cve-check):
// affected -> unpatched, not_affected -> ignored, fixed -> fixed. Whether the CVE matters for
// this image is decided per CVE across every component that carries it: a CVE only stops
// mattering when none of its carriers ship. That is package-level evidence only.

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/corefense-security/trowl/internal/pyjson"
)

var statusOfVex = map[string]string{"affected": "unpatched", "not_affected": "ignored", "fixed": "fixed",
	"under_investigation": "unknown", "": "unknown"}

// Worst first: the row shows the worst status among the carriers that decide it.
var statusOrder = []string{"unpatched", "unknown", "ignored", "fixed"}

var shippedOfRecipe = map[string]string{"present": "yes", "build-only": "build", "absent": "no", "unknown": "unknown"}
var vectors = map[string]string{"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
var avRe = regexp.MustCompile(`\bAV:([NALP])\b`)

// Fixed CVEs are most of the list (≈20k on a Yocto image) and rarely opened; keep their
// summaries short so the self-contained dashboard stays small.
const fixedSummaryChars = 240

// source says where a carrier's status comes from: the SBOM's own VEX, or trowl's match
// of the component's version against the CVE data.
func source(sb *Sbom, cve, comp string) string {
	if sb.Matched(cve, comp) {
		return "version-match"
	}
	return "sbom"
}

func statusIndex(s string) int {
	for i, x := range statusOrder {
		if x == s {
			return i
		}
	}
	return len(statusOrder)
}

func or(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func trim(text string, n int) string {
	if utf8.RuneCountInString(text) <= n {
		return text
	}
	cut := string([]rune(text)[:n])
	if i := strings.LastIndex(cut, " "); i >= 0 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,.;:") + "…"
}

func severity(score float64, has bool) string {
	switch {
	case !has || score <= 0:
		return "none"
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	}
	return "low"
}

// pickCVSS takes the highest of v3/v4; v2 only when nothing newer exists.
func pickCVSS(vi *VulnInfo) *pyjson.Obj {
	var best *pyjson.Obj
	var bestScore float64
	for _, ver := range vi.CVSSOrder {
		if ver != "3" && ver != "4" {
			continue
		}
		c := vi.CVSS[ver]
		if best == nil || c.Score > bestScore {
			best = pyjson.O("score", c.Score, "vector", c.Vector, "severity", c.Severity, "version", ver)
			bestScore = c.Score
		}
	}
	if best == nil {
		if c, ok := vi.CVSS["2"]; ok {
			best = pyjson.O("score", c.Score, "vector", c.Vector, "severity", c.Severity, "version", "2")
		}
	}
	return best
}

type carrier struct {
	obj     *pyjson.Obj
	name    string
	shipped string
	status  string
	kernel  bool
}

func BuildCVEs(sb *Sbom, status *Status) []*pyjson.Obj {
	var order []string
	carriers := map[string][]*carrier{}
	for _, comp := range sb.Vulns.Keys {
		pkg, ok := sb.Packages[comp]
		if !ok {
			continue
		}
		recipeStatus := status.Of(comp)
		if recipeStatus == "" {
			recipeStatus = "unknown"
		}
		kernel := false
		for _, c := range pkg.Cpes {
			if strings.Contains(c, ":linux_kernel:") {
				kernel = true
			}
		}
		for _, cve := range sb.Vulns.M[comp] {
			shipped := or(shippedOfRecipe, recipeStatus, "unknown")
			st := or(statusOfVex, sb.Vex(cve, comp), "unknown")
			fix := sb.FixOf(cve, comp)
			c := &carrier{name: pkg.Name, shipped: shipped, status: st, kernel: kernel,
				obj: pyjson.O("name", pkg.Name, "version", pkg.Version, "shipped", shipped, "status", st,
					"notes", sb.VexNotes(cve, comp), "kernel", kernel, "source", source(sb, cve, comp),
					"fixed_in", fix.Version, "fix_commit", fix.Commit, "backport", fix.Backport,
					"mainline", fix.Mainline, "mainline_commit", fix.MainlineCommit,
					"stable", fix.Stable, "stable_commit", fix.StableCommit)}
			if _, ok := carriers[cve]; !ok {
				order = append(order, cve)
			}
			carriers[cve] = append(carriers[cve], c)
		}
	}

	type row struct {
		obj    *pyjson.Obj
		status string
		score  float64
		id     string
	}
	var rows []row
	for _, cve := range order {
		cs := carriers[cve]
		sort.SliceStable(cs, func(i, j int) bool {
			a, b := cs[i].shipped != "yes", cs[j].shipped != "yes"
			if a != b {
				return !a
			}
			return cs[i].name < cs[j].name
		})
		var deciding []*carrier
		for _, c := range cs {
			if c.shipped == "yes" {
				deciding = append(deciding, c)
			}
		}
		if len(deciding) == 0 {
			deciding = cs
		}
		rowStatus := deciding[0].status
		for _, c := range deciding[1:] {
			if statusIndex(c.status) < statusIndex(rowStatus) {
				rowStatus = c.status
			}
		}
		kinds := map[string]bool{}
		kernel := false
		for _, c := range cs {
			kinds[c.shipped] = true
			kernel = kernel || c.kernel
		}
		var rowShipped string
		for _, k := range []string{"yes", "unknown", "no", "build"} {
			if kinds[k] {
				rowShipped = k
				break
			}
		}
		vi := sb.VulnInfo[cve]
		var cvss *pyjson.Obj
		summary, published := "", ""
		if vi != nil {
			cvss = pickCVSS(vi)
			summary, published = vi.Description, vi.Published
		}
		score, hasScore := 0.0, false
		vector := ""
		var cvssOut any
		if cvss != nil {
			cvssOut = cvss
			score, hasScore = cvss.G("score").(float64), true
			if m := avRe.FindStringSubmatch(cvss.G("vector").(string)); m != nil {
				vector = vectors[m[1]]
			}
		}
		if rowStatus == "fixed" {
			summary = trim(summary, fixedSummaryChars)
		}
		list := make([]any, len(cs))
		for i, c := range cs {
			list[i] = c.obj
		}
		rows = append(rows, row{status: rowStatus, score: score, id: cve, obj: pyjson.O(
			"id", cve, "status", rowStatus, "shipped", rowShipped,
			"cvss", cvssOut, "severity", severity(score, hasScore),
			"vector", vector,
			"summary", summary, // the SBOM's own CVE description
			"published", published,
			"kernel", kernel,
			"carriers", list, "kev", nil, "epss", nil, "links", nil)})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if statusIndex(a.status) != statusIndex(b.status) {
			return statusIndex(a.status) < statusIndex(b.status)
		}
		if a.score != b.score {
			return a.score > b.score
		}
		return a.id < b.id
	})
	out := make([]*pyjson.Obj, len(rows))
	for i, r := range rows {
		out[i] = r.obj
	}
	return out
}

func Summary(rows []*pyjson.Obj) *pyjson.Obj {
	var openShipped []*pyjson.Obj
	statusCount, sevCount := pyjson.NewCounter(), pyjson.NewCounter()
	notShipped, high, kev := 0, 0, 0
	for _, r := range rows {
		statusCount.Add(r.G("status").(string), 1)
		if r.G("status") == "unpatched" {
			if r.G("shipped") == "yes" {
				openShipped = append(openShipped, r)
			} else {
				notShipped++
			}
		}
	}
	var compOrder []string
	byComp := map[string]*pyjson.Counter{}
	for _, r := range openShipped {
		sev := r.G("severity").(string)
		sevCount.Add(sev, 1)
		if sev == "high" || sev == "critical" {
			high++
		}
		if k := r.G("kev"); k != nil {
			kev++
		}
		for _, c := range r.G("carriers").([]any) {
			co := c.(*pyjson.Obj)
			if co.G("shipped") == "yes" && co.G("status") == "unpatched" {
				name := co.G("name").(string)
				if _, ok := byComp[name]; !ok {
					byComp[name] = pyjson.NewCounter()
					compOrder = append(compOrder, name)
				}
				byComp[name].Add(sev, 1)
			}
		}
	}
	total := func(name string) int {
		t := 0
		for _, k := range byComp[name].Keys() {
			t += byComp[name].Get(k)
		}
		return t
	}
	sort.SliceStable(compOrder, func(i, j int) bool { return total(compOrder[i]) > total(compOrder[j]) })
	comps := []any{}
	for _, name := range compOrder {
		o := pyjson.O("name", name)
		for _, k := range byComp[name].Keys() {
			o.Set(k, byComp[name].Get(k))
		}
		comps = append(comps, o)
	}
	return pyjson.O(
		"status", statusCount,
		"unpatched_shipped", len(openShipped),
		"unpatched_not_shipped", notShipped,
		"high", high,
		"kev", kev,
		"severity", sevCount,
		"by_component", comps,
	)
}
