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

// cisa.gov refuses scripted clients; CISA publishes the same catalogue on GitHub.
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
			os.WriteFile(path, body, 0o644)
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

// exists is true on 200, false on 404 / redirect-away, nil when the answer was unclear.
func exists(url string) *bool {
	t, f := true, false
	for attempt := 0; attempt < 4; attempt++ {
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
			}
		}
		time.Sleep(time.Duration(1<<attempt) * time.Second)
	}
	return nil
}

// Each link is a fixed pattern; the check only asks whether that page exists. cve.org's page
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

// checkOne asks which pages exist for this CVE; nil when any answer was unclear (retried next scan).
func checkOne(cve string, kernel bool) *pyjson.Obj {
	rec := pyjson.New()
	kinds := []string{"cve", "osv"}
	if kernel {
		kinds = append(kinds, "kernel")
	}
	for _, kind := range kinds {
		ok := exists(fill(probes[kind], cve))
		if ok == nil {
			return nil
		}
		rec.Set(kind, *ok)
	}
	// nvd.nist.gov answers scripted clients with 403, so it can't be probed. NVD imports every
	// CVE List record, so a record on cve.org is taken as the NVD page existing.
	rec.Set("nvd", rec.G("cve"))
	return rec
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

// CheckLinks returns confirmed advisory links per CVE; the kernel CNA page is only tried for
// kernel CVEs. CVEs whose check failed are left out.
func CheckLinks(cache string, cves []string, kernel map[string]bool) map[string][]any {
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
	var todo []string
	for _, c := range cves {
		_, hasKernel := known[c]["kernel"]
		if now-tOf(c) > linkTTL || (kernel[c] && !hasKernel) {
			todo = append(todo, c)
		}
	}
	if len(todo) > 0 {
		results := make([]*pyjson.Obj, len(todo))
		var wg sync.WaitGroup
		next := make(chan int)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					results[i] = checkOne(todo[i], kernel[todo[i]])
				}
			}()
		}
		for i := range todo {
			next <- i
		}
		close(next)
		wg.Wait()
		for i, c := range todo {
			if rec := results[i]; rec != nil {
				m := map[string]any{}
				for _, k := range rec.Keys() {
					m[k] = rec.G(k)
				}
				m["t"] = now
				if _, ok := known[c]; !ok {
					order = append(order, c)
				}
				known[c] = m
				knownKeys[c] = append(rec.Keys(), "t")
			}
		}
		failed := 0
		for _, c := range todo {
			if tOf(c) != now {
				failed++
			}
		}
		if failed > 0 {
			warn("advisory check failed for %d CVE(s); their links are omitted", failed)
		}
		os.MkdirAll(cache, 0o755)
		os.WriteFile(path, []byte(encodeOrdered(known, order)), 0o644)
	}
	out := map[string][]any{}
	for _, c := range cves {
		if rec, ok := known[c]; ok {
			out[c] = links(c, rec)
		}
	}
	return out
}

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
