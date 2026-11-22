package feeds

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func blockRequests(t *testing.T) {
	t.Helper()
	var calls atomic.Int64
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}, Request: r}, nil
	})
	t.Cleanup(func() {
		http.DefaultTransport = old
		if n := calls.Load(); n != 0 {
			t.Errorf("offline loaders made %d HTTP requests", n)
		}
	})
}

func writeCache(t *testing.T, dir, name string, raw []byte, age time.Duration) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		after, err := os.Stat(path)
		if err != nil {
			t.Error(err)
			return
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, raw) || !after.ModTime().Equal(before.ModTime()) {
			t.Errorf("cache file %s changed", name)
		}
	})
}

func TestOfflineFeeds(t *testing.T) {
	blockRequests(t)
	for _, age := range []time.Duration{time.Minute, 30 * 24 * time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			dir := t.TempDir()
			writeCache(t, dir, "kev.json", []byte(`{"catalogVersion":"2026.11.21","dateReleased":"2026-11-21","vulnerabilities":[{"cveID":"CVE-2026-1","knownRansomwareCampaignUse":"Known"}]}`), age)
			var zipped bytes.Buffer
			w := gzip.NewWriter(&zipped)
			fmt.Fprintln(w, "#model_version:v1,score_date:2026-11-21\ncve,epss,percentile\nCVE-2026-1,0.75,0.99\nCVE-2026-2,0.1,0.2")
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			writeCache(t, dir, "epss.csv.gz", zipped.Bytes(), age)
			kev, meta := KEV(dir, false)
			if len(kev) != 1 || meta == nil || kev["CVE-2026-1"] == nil || kev["CVE-2026-1"].G("ransomware") != true {
				t.Fatalf("KEV = %v, metadata = %v", kev, meta)
			}
			epss, meta := EPSS(dir, map[string]bool{"CVE-2026-1": true}, false)
			if len(epss) != 1 || meta == nil || epss["CVE-2026-1"] == nil || epss["CVE-2026-1"].G("score") != 0.75 || meta.G("date") != "2026-11-21" {
				t.Fatalf("EPSS = %v, metadata = %v", epss, meta)
			}
		})
	}
}

func TestOfflineCacheUnavailable(t *testing.T) {
	blockRequests(t)
	for _, state := range []string{"missing", "malformed", "unreadable"} {
		t.Run(state, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "cache")
			if state != "missing" {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"kev.json", "epss.csv.gz", "links-v2.json"} {
					if state == "unreadable" {
						if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
							t.Fatal(err)
						}
					} else {
						writeCache(t, dir, name, []byte("invalid cache"), 30*24*time.Hour)
					}
				}
			}
			if got, meta := KEV(dir, false); len(got) != 0 || meta != nil {
				t.Errorf("KEV = %v, metadata = %v", got, meta)
			}
			if got, meta := EPSS(dir, map[string]bool{"CVE-1": true}, false); len(got) != 0 || meta != nil {
				t.Errorf("EPSS = %v, metadata = %v", got, meta)
			}
			if got := CheckLinks(dir, []string{"CVE-1"}, nil, nil, false); len(got) != 0 {
				t.Errorf("links = %v", got)
			}
			if state == "missing" {
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Errorf("offline loaders created the cache: %v", err)
				}
			}
		})
	}
}

func TestOfflineLinks(t *testing.T) {
	blockRequests(t)
	for _, stamp := range []int64{time.Now().Unix(), 1} {
		t.Run(fmt.Sprint(stamp), func(t *testing.T) {
			dir := t.TempDir()
			raw := []byte(fmt.Sprintf(`{"CVE-1":{"nvd":true,"cve":true,"osv":false,"t":%d},"CVE-unused":{"osv":true,"t":1}}`, stamp))
			writeCache(t, dir, "links-v2.json", raw, time.Minute)
			// Missing kernel checks must not trigger a probe while offline.
			got := CheckLinks(dir, []string{"CVE-1", "CVE-missing"}, map[string]bool{"CVE-1": true}, nil, false)
			if len(got) != 1 || len(got["CVE-1"]) != 2 {
				t.Fatalf("links = %v", got)
			}
		})
	}
}

func TestCachedOnlineRefresh(t *testing.T) {
	for _, age := range []time.Duration{time.Minute, 30 * 24 * time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "feed")
			if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			stamp := time.Now().Add(-age)
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			calls := 0
			old := http.DefaultTransport
			http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString("new")), Header: http.Header{}, Request: r}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = old })
			want, wantCalls := "old", 0
			if age > 24*time.Hour {
				want, wantCalls = "new", 1
			}
			if got := string(cached(dir, "feed", []string{"https://feed.test/data"}, day, true)); got != want || calls != wantCalls {
				t.Fatalf("cache = %q, requests = %d; want %q, %d", got, calls, want, wantCalls)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != want {
				t.Errorf("saved cache = %q, error = %v", got, err)
			}
		})
	}
}

// fakeProbes points every site at a local server, and returns the sites that were asked.
func fakeProbes(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, r.URL.Path[1:])
	}))
	t.Cleanup(srv.Close)
	old := probes
	probes = map[string]string{"cve": srv.URL + "/cve", "osv": srv.URL + "/osv", "kernel": srv.URL + "/kernel"}
	t.Cleanup(func() { probes = old })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return asked
	}
}

func TestNewCheck(t *testing.T) {
	for _, c := range []struct {
		name       string
		inFeed     map[string]bool
		kernel     bool
		wantKernel any
		wantAsked  []string
	}{
		{"kernel CVE on the CNA's tree", map[string]bool{"CVE-1": true}, true, true, []string{"osv"}},
		{"kernel CVE not on it", map[string]bool{"CVE-1": false}, true, false, []string{"osv"}},
		{"userland CVE", map[string]bool{"CVE-1": false}, false, nil, []string{"osv"}},
		{"not in the feed", map[string]bool{"CVE-2": true}, true, true, []string{"cve", "osv", "kernel"}},
		{"no feed at all", nil, true, true, []string{"cve", "osv", "kernel"}},
	} {
		asked := fakeProbes(t)
		chk := newCheck("CVE-1", c.kernel, c.inFeed)
		probe([]*linkCheck{chk}, 1, nil)
		if len(chk.ask) > 0 {
			t.Fatalf("%s: unanswered %v", c.name, chk.ask)
		}
		rec := chk.record()
		if rec["cve"] != true || rec["nvd"] != true || rec["osv"] != true {
			t.Errorf("%s: cve, nvd and osv should all exist: %v %v %v", c.name, rec["cve"], rec["nvd"], rec["osv"])
		}
		if got := rec["kernel"]; got != c.wantKernel {
			t.Errorf("%s: kernel %v, want %v", c.name, got, c.wantKernel)
		}
		if got := asked(); len(got) != len(c.wantAsked) {
			t.Errorf("%s: asked %v, want %v", c.name, got, c.wantAsked)
		} else {
			for i := range got {
				if got[i] != c.wantAsked[i] {
					t.Errorf("%s: asked %v, want %v", c.name, got, c.wantAsked)
				}
			}
		}
	}
}

// A site that rate-limits a burst of requests answers clearly later. Every CVE should still get
// its links in the same scan, instead of being left without them until the next.
func TestCheckLinksRetriesUnclearAnswers(t *testing.T) {
	var mu sync.Mutex
	refused := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		// The first 60 OSV requests are rate limited. That is more than the in-request retries
		// ride out.
		if r.URL.Path == "/osv" && refused < 60 {
			refused++
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	t.Cleanup(srv.Close)
	oldProbes, oldSleep := probes, sleep
	probes = map[string]string{"cve": srv.URL + "/cve", "osv": srv.URL + "/osv", "kernel": srv.URL + "/kernel"}
	sleep = func(time.Duration) {}
	t.Cleanup(func() { probes, sleep = oldProbes, oldSleep })

	var cves []string
	inFeed := map[string]bool{}
	for i := 0; i < 20; i++ {
		c := fmt.Sprintf("CVE-2026-%d", i)
		cves, inFeed[c] = append(cves, c), false
	}
	got := CheckLinks(t.TempDir(), cves, nil, inFeed, true)
	for _, c := range cves {
		if len(got[c]) != 3 { // nvd, osv, cve
			t.Errorf("%s: links %v", c, got[c])
		}
	}
}
