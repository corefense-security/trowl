// Package nvd matches SBOM components to CVEs by version, the way Trivy, Grype and Yocto's
// cve-check do, for SBOMs that carry no CVE assessment of their own.
//
// The data is the NVD feed mirrored by fkie-cad/nvd-json-data-feeds: one xz file per year,
// cached under the cache directory and refreshed daily. Userland components are matched by
// CPE against NVD's configurations. Linux kernel CVEs are matched against the kernel CNA's
// version ranges first, since NVD has not analysed most recent ones; NVD's configurations are
// the fallback.
//
// A version match can't see fixes backported without a version change, so it may report CVEs
// that the build has already patched.
package nvd

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ulikunitz/xz"
)

const (
	releaseURL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
	firstYear  = 1999
	maxAge     = 24 * time.Hour
	// kernelCNA is the Linux kernel CNA's source id in NVD records.
	kernelCNA = "416baaa9-dc9f-4396-8d5f-8c081fb06d67"
)

// Target is one SBOM component to match: its CPE vendor ("*" for any), product and version.
type Target struct {
	Comp            string
	Vendor, Product string
	Version         string
}

// Kernel reports whether the target is the Linux kernel.
func (t Target) Kernel() bool { return t.Product == "linux_kernel" }

type CVSS struct {
	Score            float64
	Vector, Severity string
}

// Info is what the dashboard needs about a matched CVE.
type Info struct {
	Description, Published string
	CVSS                   map[string]*CVSS // by major version: "2", "3", "4"
	CVSSOrder              []string
}

// Match is one CVE that affects one component.
type Match struct {
	Comp, CVE string
}

// Result is the outcome of a match run.
type Result struct {
	Matches []Match
	Info    map[string]*Info
	Meta    map[string]any // for the report's sources
}

func warn(format string, a ...any) { fmt.Fprintf(os.Stderr, "trowl: "+format+"\n", a...) }

// Run fetches the feed when network is allowed and the cache is stale, then matches. It returns
// nil when there is no feed to match against.
func Run(cacheDir string, network bool, targets []Target) *Result {
	if len(targets) == 0 {
		return nil
	}
	dir := filepath.Join(cacheDir, "nvd")
	years := yearsUpTo(time.Now().UTC().Year())
	if network {
		fetch(dir, years)
	}
	var files []string
	for _, y := range years {
		if p := filepath.Join(dir, y+".json.xz"); fileExists(p) {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		warn("no NVD data cached; CVEs come from the SBOM only")
		return nil
	}
	res := match(files, targets)
	updated := ""
	if st, err := os.Stat(filepath.Join(dir, "CVE-all.updated")); err == nil {
		updated = st.ModTime().UTC().Format(time.RFC3339)
	}
	res.Meta = map[string]any{"source": "fkie-cad/nvd-json-data-feeds", "updated": updated, "years": len(files)}
	return res
}

func yearsUpTo(last int) []string {
	var out []string
	for y := firstYear; y <= last; y++ {
		out = append(out, "CVE-"+strconv.Itoa(y))
	}
	return out
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// fetch refreshes each year's file when its published checksum changed. The whole feed is
// checked at most once a day.
func fetch(dir string, years []string) {
	stamp := filepath.Join(dir, "CVE-all.updated")
	if st, err := os.Stat(stamp); err == nil && time.Since(st.ModTime()) < maxAge {
		return
	}
	os.MkdirAll(dir, 0o755)
	warn("updating NVD data (%d yearly files)", len(years))
	client := &http.Client{Timeout: 10 * time.Minute}
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	sem := make(chan struct{}, 6)
	for _, y := range years {
		wg.Add(1)
		go func(y string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := fetchYear(client, dir, y); err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				warn("NVD %s: %v", y, err)
			}
		}(y)
	}
	wg.Wait()
	if failed == 0 {
		os.WriteFile(stamp, nil, 0o644)
		now := time.Now()
		os.Chtimes(stamp, now, now)
	}
}

func get(client *http.Client, url string) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		resp, err := client.Get(url)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			if resp.StatusCode == 404 {
				return nil, last
			}
			continue
		}
		if err != nil {
			last = err
			continue
		}
		return body, nil
	}
	return nil, last
}

// metaSHA reads the sha256 line of a feed .meta file.
func metaSHA(meta []byte) string {
	for _, line := range strings.Split(string(meta), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "sha256:"); ok {
			return strings.ToLower(v)
		}
	}
	return ""
}

func fetchYear(client *http.Client, dir, year string) error {
	meta, err := get(client, releaseURL+year+".meta")
	if err != nil {
		return err
	}
	data := filepath.Join(dir, year+".json.xz")
	metaPath := filepath.Join(dir, year+".meta")
	if old, err := os.ReadFile(metaPath); err == nil && metaSHA(old) == metaSHA(meta) && fileExists(data) {
		return nil
	}
	body, err := get(client, releaseURL+year+".json.xz")
	if err != nil {
		return err
	}
	// The .meta checksum is of the uncompressed JSON; verify it before replacing the cache.
	want := metaSHA(meta)
	if want != "" {
		r, err := xz.NewReader(strings.NewReader(string(body)))
		if err != nil {
			return err
		}
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return fmt.Errorf("checksum mismatch")
		}
	}
	tmp := data + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, data); err != nil {
		return err
	}
	return os.WriteFile(metaPath, meta, 0o644)
}

// --- feed records ---

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type node struct {
	CpeMatch []cpeMatch `json:"cpeMatch"`
}

type cnaVersion struct {
	Version         string `json:"version"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	VersionType     string `json:"versionType"`
	Status          string `json:"status"`
}

type affectedData struct {
	Vendor        string       `json:"vendor"`
	Product       string       `json:"product"`
	DefaultStatus string       `json:"defaultStatus"`
	Versions      []cnaVersion `json:"versions"`
}

type cvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type metric struct {
	Source       string   `json:"source"`
	Type         string   `json:"type"`
	CvssData     cvssData `json:"cvssData"`
	BaseSeverity string   `json:"baseSeverity"` // v2 keeps it here
}

type record struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []metric `json:"cvssMetricV40"`
		V31 []metric `json:"cvssMetricV31"`
		V30 []metric `json:"cvssMetricV30"`
		V2  []metric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []node `json:"nodes"`
	} `json:"configurations"`
	Affected []struct {
		Source       string         `json:"source"`
		AffectedData []affectedData `json:"affectedData"`
	} `json:"affected"`
}

// --- matching ---

func match(files []string, targets []Target) *Result {
	byProduct := map[string][]Target{}
	seenTarget := map[Target]bool{}
	for _, t := range targets {
		// Yocto gives the kernel recipe both linux:linux_kernel and linux:linux; both mean the
		// kernel, which is matched once, with the kernel rules.
		if t.Product == "linux" && (t.Vendor == "linux" || t.Vendor == "*") {
			t.Product, t.Vendor = "linux_kernel", "*"
		}
		if seenTarget[t] {
			continue
		}
		seenTarget[t] = true
		byProduct[t.Product] = append(byProduct[t.Product], t)
	}
	res := &Result{Info: map[string]*Info{}}
	var mu sync.Mutex
	seen := map[Match]bool{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for _, f := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			err := eachRecord(f, func(rec *record) {
				comps := affects(rec, byProduct)
				if len(comps) == 0 {
					return
				}
				info := infoOf(rec)
				mu.Lock()
				defer mu.Unlock()
				for _, c := range comps {
					m := Match{c, rec.ID}
					if !seen[m] {
						seen[m] = true
						res.Matches = append(res.Matches, m)
					}
				}
				res.Info[rec.ID] = info
			})
			if err != nil {
				warn("NVD %s: %v", filepath.Base(f), err)
			}
		}(f)
	}
	wg.Wait()
	sort.Slice(res.Matches, func(i, j int) bool {
		if res.Matches[i].Comp != res.Matches[j].Comp {
			return res.Matches[i].Comp < res.Matches[j].Comp
		}
		return res.Matches[i].CVE < res.Matches[j].CVE
	})
	return res
}

// eachRecord streams the records of one feed file.
func eachRecord(path string, fn func(*record)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := xz.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if s, ok := tok.(string); ok && s == "cve_items" {
			break
		}
	}
	if _, err := dec.Token(); err != nil { // [
		return err
	}
	for dec.More() {
		var rec record
		if err := dec.Decode(&rec); err != nil {
			return err
		}
		if rec.VulnStatus == "Rejected" {
			continue
		}
		fn(&rec)
	}
	return nil
}

// affects returns the components a record affects. For each product the CNA's own version
// data decides when it has any (NVD has not analysed most recent CVEs); NVD's CPE
// configurations are the fallback. That is the precedence sbom-cve-check uses.
func affects(rec *record, byProduct map[string][]Target) []string {
	var out []string
	for product, ts := range byProduct {
		kernel := product == "linux_kernel"
		blocks := cnaBlocks(rec, product, kernel)
		if len(blocks) > 0 {
			for _, t := range ts {
				hit := false
				if kernel {
					hit = kernelAffected(t.Version, blocks)
				} else {
					for _, b := range blocks {
						if cnaAffected(t.Version, b, false) && vendorAgrees(t.Vendor, b.Vendor) {
							hit = true
							break
						}
					}
				}
				if hit {
					out = append(out, t.Comp)
				}
			}
			continue
		}
		if !mentions(rec, product) {
			continue
		}
		out = append(out, cpeAffects(rec, ts)...)
	}
	return dedupe(out)
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := xs[:0]
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// cnaBlocks returns the CNA's affected blocks for a product that carry at least one version
// entry trowl can compare. The kernel's come only from the kernel CNA; other products
// match by name (case-insensitive) against the CPE product.
func cnaBlocks(rec *record, product string, kernel bool) []affectedData {
	var out []affectedData
	for _, a := range rec.Affected {
		if kernel && a.Source != kernelCNA {
			continue
		}
		for _, ad := range a.AffectedData {
			name := strings.ToLower(strings.TrimSpace(ad.Product))
			if kernel {
				if name != "linux" {
					continue
				}
			} else if strings.ReplaceAll(name, " ", "_") != product && strings.ReplaceAll(name, " ", "-") != product {
				continue
			}
			for _, v := range ad.Versions {
				if usable(v) {
					out = append(out, ad)
					break
				}
			}
		}
	}
	return out
}

// usable reports whether a CNA version entry can be compared: not a git commit or a distro
// package version, and not a placeholder such as "n/a" or "unspecified".
func usable(v cnaVersion) bool {
	switch v.VersionType {
	case "git", "rpm", "deb", "maven", "npm", "pypi":
		return false
	}
	ver := strings.ToLower(strings.TrimSpace(v.Version))
	if ver == "" || ver == "n/a" || ver == "unspecified" || ver == "unknown" || strings.HasPrefix(ver, "not") {
		return false
	}
	return strings.ContainsAny(ver, "0123456789")
}

// cnaAffected reads one CNA block (CVE 5 "affected" semantics): any matching "unaffected"
// entry clears the version; otherwise it is affected when an affected entry or the default
// says so.
func cnaAffected(v string, b affectedData, kernel bool) bool {
	affected := b.DefaultStatus == "affected"
	for _, e := range b.Versions {
		if !usable(e) || !entryHits(v, e, kernel) {
			continue
		}
		if e.Status == "unaffected" {
			return false
		}
		if e.Status == "affected" {
			affected = true
		}
	}
	if affected && kernel && fixedInOlderSeries(v, b) {
		return false
	}
	return affected
}

// kernelAffected reads all of a kernel CVE's CNA blocks together. The kernel CNA writes one
// block of affected ranges per stable branch and one of fixed versions. A branch range with a
// real start ("6.18.20 <= v < 6.18.54": the bug was backported into that branch) is the most
// precise statement and decides first; otherwise an "unaffected" entry in either block clears
// the version.
func kernelAffected(v string, blocks []affectedData) bool {
	for _, b := range blocks {
		for _, e := range b.Versions {
			if usable(e) && e.Status == "affected" && e.LessThan != "" && e.Version != "0" &&
				Compare(v, e.Version) >= 0 && Compare(v, e.LessThan) < 0 {
				return true
			}
		}
	}
	merged := affectedData{DefaultStatus: "unaffected"}
	for _, b := range blocks {
		if b.DefaultStatus == "affected" {
			merged.DefaultStatus = "affected"
		}
		merged.Versions = append(merged.Versions, b.Versions...)
	}
	return cnaAffected(v, merged, true)
}

// vendorAgrees: when the SBOM names a CPE vendor, the CNA's vendor must not name a different
// one ("ruby" for the Ruby zlib gem is not "gnu" or "zlib").
func vendorAgrees(cpeVendor, cnaVendor string) bool {
	if cpeVendor == "" || cpeVendor == "*" {
		return true
	}
	norm := func(x string) string {
		x = strings.ToLower(x)
		for _, w := range []string{" project", " inc.", " inc", " ltd", " foundation", " team"} {
			x = strings.TrimSuffix(x, w)
		}
		return strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, x)
	}
	a, b := norm(cpeVendor), norm(cnaVendor)
	return b == "" || b == "na" || strings.Contains(b, a) || strings.Contains(a, b)
}

// fixedInOlderSeries: the kernel CNA lists one fix per stable series. A version newer than the
// newest series with a fix contains it, even when the record has no mainline entry (common in
// CVEs assigned years after the fix). sbom-cve-check reads the records the same way.
func fixedInOlderSeries(v string, b affectedData) bool {
	top := ""
	for _, e := range b.Versions {
		if e.Status != "unaffected" || !usable(e) || e.LessThan != "" {
			continue
		}
		if e.LessThanOrEqual == "*" || strings.HasSuffix(e.LessThanOrEqual, ".*") {
			if top == "" || Compare(e.Version, top) > 0 {
				top = e.Version
			}
		}
	}
	return top != "" && Compare(v, top) >= 0
}

func entryHits(v string, e cnaVersion, kernel bool) bool {
	ver := strings.TrimSpace(e.Version)
	if strings.ContainsAny(ver, "<>=") { // GitHub style: ">= 2.17, <= 2.41.6"
		return constraintsHit(v, ver)
	}
	switch {
	case e.LessThan != "":
		return (ver == "0" || Compare(v, ver) >= 0) && (e.LessThan == "*" || Compare(v, e.LessThan) < 0)
	case e.LessThanOrEqual == "*":
		return ver == "0" || Compare(v, ver) >= 0
	case strings.HasSuffix(e.LessThanOrEqual, ".*"):
		series := strings.TrimSuffix(e.LessThanOrEqual, "*") // "6.18."
		return Compare(v, ver) >= 0 && strings.HasPrefix(v+".", series)
	case e.LessThanOrEqual != "":
		return (ver == "0" || Compare(v, ver) >= 0) && Compare(v, e.LessThanOrEqual) <= 0
	}
	// A bare kernel version marked affected is the release that introduced the bug.
	if kernel && e.Status == "affected" {
		return Compare(v, ver) >= 0
	}
	return Compare(v, ver) == 0
}

// constraintsHit evaluates comma-separated constraints such as ">= 2.17, < 2.41.6".
func constraintsHit(v, expr string) bool {
	any := false
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		op := strings.TrimRight(part[:len(part)-len(strings.TrimLeft(part, "<>=! "))], " ")
		want := strings.TrimSpace(strings.TrimLeft(part, "<>=! "))
		if want == "" {
			continue
		}
		c := Compare(v, want)
		ok := false
		switch op {
		case ">=":
			ok = c >= 0
		case ">":
			ok = c > 0
		case "<=":
			ok = c <= 0
		case "<":
			ok = c < 0
		case "=", "==", "":
			ok = c == 0
		default:
			return false
		}
		if !ok {
			return false
		}
		any = true
	}
	return any
}

// mentions is a quick filter: does any CPE in the record name this product?
func mentions(rec *record, product string) bool {
	needle := ":" + product + ":"
	for _, c := range rec.Configurations {
		for _, n := range c.Nodes {
			for _, m := range n.CpeMatch {
				if strings.Contains(m.Criteria, needle) {
					return true
				}
			}
		}
	}
	return false
}

// cpeAffects matches the record's vulnerable CPEs against targets of one product.
func cpeAffects(rec *record, ts []Target) []string {
	var out []string
	for _, t := range ts {
		if cpeHit(rec, t) {
			out = append(out, t.Comp)
		}
	}
	return out
}

func cpeHit(rec *record, t Target) bool {
	for _, c := range rec.Configurations {
		for _, n := range c.Nodes {
			for _, m := range n.CpeMatch {
				if !m.Vulnerable {
					continue
				}
				p := splitCPE(m.Criteria)
				if len(p) < 7 || p[4] != t.Product {
					continue
				}
				if t.Vendor != "*" && t.Vendor != "" && p[3] != t.Vendor {
					continue
				}
				if inRange(t.Version, p[5], p[6], m) {
					return true
				}
			}
		}
	}
	return false
}

// inRange decides whether version v is covered by one cpeMatch entry.
func inRange(v, cpeVersion, cpeUpdate string, m cpeMatch) bool {
	ranged := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
		m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
	if ranged {
		if m.VersionStartIncluding != "" && Compare(v, m.VersionStartIncluding) < 0 {
			return false
		}
		if m.VersionStartExcluding != "" && Compare(v, m.VersionStartExcluding) <= 0 {
			return false
		}
		if m.VersionEndIncluding != "" && Compare(v, m.VersionEndIncluding) > 0 {
			return false
		}
		if m.VersionEndExcluding != "" && Compare(v, m.VersionEndExcluding) >= 0 {
			return false
		}
		return true
	}
	switch cpeVersion {
	case "*":
		return true // every version
	case "-", "":
		return false // "not applicable"; not a version claim
	}
	want := cpeVersion
	if cpeUpdate != "*" && cpeUpdate != "-" && cpeUpdate != "" {
		want += cpeUpdate // openssh 10.3 + p1 = 10.3p1
	}
	return Compare(v, want) == 0
}

// splitCPE splits a CPE 2.3 string on unescaped colons.
func splitCPE(s string) []string {
	var parts []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(parts, cur.String())
}

func infoOf(rec *record) *Info {
	info := &Info{Published: rec.Published, CVSS: map[string]*CVSS{}}
	for _, d := range rec.Descriptions {
		if d.Lang == "en" {
			info.Description = d.Value
			break
		}
	}
	pick := func(major string, ms []metric) {
		if len(ms) == 0 {
			return
		}
		best := ms[0]
		for _, m := range ms {
			if m.Type == "Primary" {
				best = m
				break
			}
		}
		sev := best.CvssData.BaseSeverity
		if sev == "" {
			sev = best.BaseSeverity
		}
		info.CVSS[major] = &CVSS{Score: best.CvssData.BaseScore, Vector: best.CvssData.VectorString,
			Severity: strings.ToLower(sev)}
		info.CVSSOrder = append(info.CVSSOrder, major)
	}
	pick("4", rec.Metrics.V40)
	if len(rec.Metrics.V31) > 0 {
		pick("3", rec.Metrics.V31)
	} else {
		pick("3", rec.Metrics.V30)
	}
	pick("2", rec.Metrics.V2)
	return info
}
