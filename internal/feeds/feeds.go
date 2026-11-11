// Package feeds fetches public data at scan time: CISA KEV, FIRST EPSS, and advisory-link checks.
//
// Everything is cached under the cache directory so CI runs can reuse it (KEV and EPSS for a
// day, link results for a week). Any network failure degrades to "not available" rather than
// failing the scan, and a link is only written into the report once its target is confirmed.
package feeds

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/corefense-security/trowl/internal/status"
)

var ua = "trowl/" + model.Version

// cisa.gov refuses scripted clients. CISA publishes the same catalogue on GitHub.
var kevURLs = []string{
	"https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
	"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

const (
	epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	day     = 86400
	linkTTL = 7 * day
	workers = 8
)

var retryCodes = map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true}

func warn(format string, a ...any) { status.Warn(format, a...) }

// get is a GET with backoff on rate limits, server errors and timeouts.
func get(url string, timeout time.Duration) (int, []byte, error) {
	client := &http.Client{Timeout: timeout}
	const tries = 4
	for attempt := 0; attempt < tries; attempt++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", ua)
		resp, err := client.Do(req)
		if err != nil {
			if attempt == tries-1 {
				return 0, nil, err
			}
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if err != nil {
				if attempt == tries-1 {
					return 0, nil, err
				}
				continue
			}
			return resp.StatusCode, body, nil
		}
		if !retryCodes[resp.StatusCode] || attempt == tries-1 {
			return resp.StatusCode, nil, nil
		}
		wait := time.Duration(1<<attempt) * time.Second
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n >= 0 {
			wait = time.Duration(min(n, 30)) * time.Second
		}
		time.Sleep(wait)
	}
	return 0, nil, nil
}

func cached(cache, name string, urls []string, maxAge float64) []byte {
	path := filepath.Join(cache, name)
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() &&
		float64(time.Now().UnixNano()-fi.ModTime().UnixNano())/1e9 < maxAge {
		b, _ := os.ReadFile(path)
		return b
	}
	for _, url := range urls {
		code, body, err := get(url, 60*time.Second)
		if err != nil {
			warn("%s: %v", url, err)
			continue
		}
		if code == 200 && len(body) > 0 {
			os.MkdirAll(cache, 0o755)
			if err := os.WriteFile(path, body, 0o644); err != nil {
				warn("can't cache %s: %v", name, err)
			}
			return body
		}
		warn("%s: HTTP %d", url, code)
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		warn("using stale %s", name)
		b, _ := os.ReadFile(path)
		return b
	}
	return nil
}

func str(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return ""
}

// KEV returns the CISA KEV entries by CVE and the catalogue's metadata (nil when unavailable).
func KEV(cache string) (map[string]*pyjson.Obj, *pyjson.Obj) {
	raw := cached(cache, "kev.json", kevURLs, day)
	if raw == nil {
		return map[string]*pyjson.Obj{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return map[string]*pyjson.Obj{}, nil
	}
	entries := map[string]*pyjson.Obj{}
	vulns, _ := doc["vulnerabilities"].([]any)
	for _, v := range vulns {
		m, _ := v.(map[string]any)
		id, _ := m["cveID"].(string)
		entries[id] = pyjson.O("added", str(m, "dateAdded"), "name", str(m, "vulnerabilityName"),
			"ransomware", str(m, "knownRansomwareCampaignUse") == "Known", "due", str(m, "dueDate"))
	}
	return entries, pyjson.O("version", str(doc, "catalogVersion"), "released", str(doc, "dateReleased"),
		"count", len(entries))
}

// EPSS returns scores for the wanted CVEs and the score file's metadata (nil when unavailable).
func EPSS(cache string, wanted map[string]bool) (map[string]*pyjson.Obj, *pyjson.Obj) {
	raw := cached(cache, "epss.csv.gz", []string{epssURL}, day)
	if raw == nil {
		return map[string]*pyjson.Obj{}, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return map[string]*pyjson.Obj{}, nil
	}
	data, _ := io.ReadAll(r)
	text := string(data)
	first, rest, _ := strings.Cut(text, "\n")
	meta := map[string]string{}
	for _, part := range strings.Split(strings.TrimLeft(first, "#"), ",") { // "#model_version:v2025.03.14,score_date:..."
		k, v, _ := strings.Cut(part, ":")
		meta[k] = v
	}
	scores := map[string]*pyjson.Obj{}
	cr := csv.NewReader(strings.NewReader(rest))
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err == nil {
		col := map[string]int{}
		for i, h := range header {
			col[h] = i
		}
		for {
			rec, err := cr.Read()
			if err != nil {
				break
			}
			cve := rec[col["cve"]]
			if !wanted[cve] {
				continue
			}
			e, _ := strconv.ParseFloat(rec[col["epss"]], 64)
			p, _ := strconv.ParseFloat(rec[col["percentile"]], 64)
			scores[cve] = pyjson.O("score", e, "percentile", p)
		}
	}
	date := meta["score_date"]
	if len(date) > 10 {
		date = date[:10]
	}
	return scores, pyjson.O("date", date, "model", meta["model_version"])
}

var noRedirect = &http.Client{
	Timeout:       20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// exists is true on 200 and false on 404 or a redirect away. It is nil when the answer was
// unclear, such as a timeout, or a rate limit or server error that outlasted the retries. A 429 is
// retried after the wait its Retry-After asks for, up to maxRetryAfter.
func exists(url string) *bool {
	t, f := true, false
	for attempt := 0; attempt < 4; attempt++ {
		wait := time.Duration(1<<attempt) * time.Second
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", ua)
		resp, err := noRedirect.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			switch code := resp.StatusCode; {
			case code == 200:
				return &t
			case code >= 200 && code < 300:
				return &f
			case code == 301 || code == 302 || code == 303 || code == 307 || code == 308 || code == 404 || code == 410:
				return &f
			case !retryCodes[code]:
				return nil
			case code == 429:
				if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
					wait = min(time.Duration(s)*time.Second, maxRetryAfter)
				}
			}
		}
		sleep(wait)
	}
	return nil
}

// maxRetryAfter caps the wait a site's Retry-After can ask for.
const maxRetryAfter = 30 * time.Second

// sleep is time.Sleep. Tests replace it.
var sleep = time.Sleep

// Each link is a fixed pattern, and the check only asks whether that page exists. cve.org's page
// answers 200 for any ID (it renders client-side), so its record API stands in for it.
var pages = map[string]string{
	"nvd":    "https://nvd.nist.gov/vuln/detail/{id}",
	"osv":    "https://osv.dev/vulnerability/{id}",
	"cve":    "https://www.cve.org/CVERecord?id={id}",
	"kernel": "https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/published/{year}/{id}.json",
}
var probes = map[string]string{
	"osv":    pages["osv"],
	"cve":    "https://cveawg.mitre.org/api/cve/{id}",
	"kernel": pages["kernel"],
}

func fill(pattern, cve string) string {
	year := ""
	if len(cve) >= 8 {
		year = cve[4:8]
	} else if len(cve) > 4 {
		year = cve[4:]
	}
	return strings.NewReplacer("{id}", cve, "{year}", year).Replace(pattern)
}

// linkCheck is one CVE's pages: those answered, and those still to ask.
type linkCheck struct {
	cve    string
	answer map[string]bool // by kind: the page exists
	ask    []string        // kinds no answer was clear for yet
}

// newCheck lists the pages to find for a CVE. These are cve.org and OSV, plus the kernel CNA's
// page for a kernel CVE. inFeed is the NVD data, as in CheckLinks. A CVE with a record there is on
// cve.org, and the record tells whether it has a kernel page, so only OSV has to be asked. A CVE
// without a record is asked of every site.
func newCheck(cve string, kernel bool, inFeed map[string]bool) *linkCheck {
	c := &linkCheck{cve: cve, answer: map[string]bool{}}
	kinds := []string{"cve", "osv"}
	if kernel {
		kinds = append(kinds, "kernel")
	}
	kernelPage, known := inFeed[cve]
	for _, kind := range kinds {
		if known && kind != "osv" {
			c.answer[kind] = kind == "cve" || kernelPage
		} else {
			c.ask = append(c.ask, kind)
		}
	}
	return c
}

// record is the cached form of a finished check. nvd.nist.gov answers scripted clients with 403,
// so it can't be probed. NVD imports every CVE List record, so a record on cve.org is taken as the
// NVD page existing.
func (c *linkCheck) record() map[string]any {
	m := map[string]any{}
	for _, k := range []string{"cve", "osv", "kernel"} {
		if v, ok := c.answer[k]; ok {
			m[k] = v
		}
	}
	m["nvd"] = c.answer["cve"]
	return m
}

func links(cve string, rec map[string]any) []any {
	out := []any{}
	for _, k := range []string{"nvd", "osv", "cve", "kernel"} {
		if b, _ := rec[k].(bool); b {
			out = append(out, pyjson.O("kind", k, "url", fill(pages[k], cve)))
		}
	}
	return out
}

// linkRounds are the passes over the pages still unanswered. The first runs at full speed and
// later ones run slower after a pause. An unclear answer is nearly always a site rate-limiting or
// briefly failing a burst of requests.
var linkRounds = []struct {
	workers int
	pause   time.Duration
}{{workers, 0}, {2, 10 * time.Second}, {1, 30 * time.Second}}

// probe asks each site the checks still need, with n requests at a time, and keeps the clear
// answers. bar, if set, ticks once per check.
func probe(checks []*linkCheck, n int, bar *status.Step) {
	type job struct {
		c    *linkCheck
		kind string
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan job)
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ok := exists(fill(probes[j.kind], j.c.cve)); ok != nil {
					mu.Lock()
					j.c.answer[j.kind] = *ok
					mu.Unlock()
				}
			}
		}()
	}
	for _, c := range checks {
		for _, kind := range c.ask {
			jobs <- job{c, kind}
		}
		if bar != nil {
			bar.Tick()
		}
	}
	close(jobs)
	wg.Wait()
	for _, c := range checks {
		var still []string
		for _, kind := range c.ask {
			if _, ok := c.answer[kind]; !ok {
				still = append(still, kind)
			}
		}
		c.ask = still
	}
}

// unanswered returns the checks some page is still unanswered for.
func unanswered(checks []*linkCheck) []*linkCheck {
	var out []*linkCheck
	for _, c := range checks {
		if len(c.ask) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// CheckLinks returns confirmed advisory links per CVE. The kernel CNA page is only tried for
// kernel CVEs. inFeed holds the CVEs with an NVD record, each true when it has a kernel CNA
// page. It is nil without NVD data.
//
// A site that doesn't answer clearly is asked again, more slowly, in later rounds (see
// linkRounds). One burst of rate limiting then doesn't leave CVEs without links. Only a CVE whose
// every page is answered gets links and is cached. A CVE still unanswered after the last round
// is left out, named in a warning with the sites, and asked again next scan.
func CheckLinks(cache string, cves []string, kernel, inFeed map[string]bool) map[string][]any {
	path := filepath.Join(cache, "links-v2.json")
	known := map[string]map[string]any{}
	var order []string
	if raw, err := os.ReadFile(path); err == nil {
		known, order = decodeOrdered(raw)
	}
	now := float64(time.Now().UnixNano()) / 1e9
	tOf := func(c string) float64 {
		t, _ := known[c]["t"].(float64)
		return t
	}
	var checks []*linkCheck
	for _, c := range cves {
		_, hasKernel := known[c]["kernel"]
		if now-tOf(c) > linkTTL || (kernel[c] && !hasKernel) {
			checks = append(checks, newCheck(c, kernel[c], inFeed))
		}
	}
	if len(checks) > 0 {
		bar := status.StartBar("advisory links", len(checks))
		probe(checks, linkRounds[0].workers, bar)
		left := unanswered(checks)
		for _, r := range linkRounds[1:] {
			if len(left) == 0 {
				break
			}
			sleep(r.pause)
			probe(left, r.workers, nil)
			left = unanswered(left)
		}
		for _, c := range checks {
			if len(c.ask) > 0 {
				continue
			}
			m := c.record()
			m["t"] = now
			if _, ok := known[c.cve]; !ok {
				order = append(order, c.cve)
			}
			known[c.cve] = m
			keys := []string{}
			for _, k := range []string{"cve", "osv", "kernel", "nvd", "t"} {
				if _, ok := m[k]; ok {
					keys = append(keys, k)
				}
			}
			knownKeys[c.cve] = keys
		}
		if len(left) > 0 {
			sites := map[string]int{}
			for _, c := range left {
				for _, k := range c.ask {
					sites[k]++
				}
			}
			var names []string
			for _, k := range []string{"cve", "osv", "kernel"} {
				if sites[k] > 0 {
					names = append(names, fmt.Sprintf("%s %d", siteNames[k], sites[k]))
				}
			}
			warn("advisory links: %d CVE(s) left without links, as some sites didn't answer clearly after %d rounds (%s); the next scan asks again",
				len(left), len(linkRounds), strings.Join(names, ", "))
		}
		if checked := len(checks) - len(left); checked > 0 {
			bar.Ok(fmt.Sprintf("%d CVEs", checked))
		} else {
			bar.Fail("none checked")
		}
		os.MkdirAll(cache, 0o755)
		if err := os.WriteFile(path, []byte(encodeOrdered(known, order)), 0o644); err != nil {
			warn("can't cache the advisory links: %v", err)
		}
	}
	out := map[string][]any{}
	for _, c := range cves {
		if rec, ok := known[c]; ok {
			out[c] = links(c, rec)
		}
	}
	return out
}

// siteNames name the sites a warning mentions.
var siteNames = map[string]string{"cve": "cveawg.mitre.org", "osv": "osv.dev", "kernel": "git.kernel.org"}

// knownKeys remembers each cached record's key order so the cache file is rewritten as Python did.
var knownKeys = map[string][]string{}

func decodeOrdered(raw []byte) (map[string]map[string]any, []string) {
	known := map[string]map[string]any{}
	var order []string
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return known, nil
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		cve, _ := tok.(string)
		var rec map[string]any
		var keys []string
		if t, err := dec.Token(); err != nil || t != json.Delim('{') {
			break
		}
		rec = map[string]any{}
		for dec.More() {
			kt, _ := dec.Token()
			k, _ := kt.(string)
			var v any
			dec.Decode(&v)
			rec[k] = v
			keys = append(keys, k)
		}
		dec.Token()
		known[cve] = rec
		knownKeys[cve] = keys
		order = append(order, cve)
	}
	return known, order
}

func encodeOrdered(known map[string]map[string]any, order []string) string {
	top := pyjson.New()
	for _, c := range order {
		rec := pyjson.New()
		for _, k := range knownKeys[c] {
			v := known[c][k]
			if f, ok := v.(float64); ok && k != "t" && f == math.Trunc(f) {
				rec.Set(k, int(f))
				continue
			}
			rec.Set(k, v)
		}
		top.Set(c, rec)
	}
	return pyjson.Default(top)
}
