package feeds

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

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

// A site that rate-limits a burst of requests answers clearly later: every CVE still gets its
// links, in the same scan, instead of being left without them until the next.
func TestCheckLinksRetriesUnclearAnswers(t *testing.T) {
	var mu sync.Mutex
	refused := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		// The first 60 OSV requests are rate limited: more than its in-request retries ride out.
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
	got := CheckLinks(t.TempDir(), cves, nil, inFeed)
	for _, c := range cves {
		if len(got[c]) != 3 { // nvd, osv, cve
			t.Errorf("%s: links %v", c, got[c])
		}
	}
}
