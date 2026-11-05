package feeds

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
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

func TestCheckOne(t *testing.T) {
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
		rec := checkOne("CVE-1", c.kernel, c.inFeed)
		if rec == nil {
			t.Fatalf("%s: no result", c.name)
		}
		if rec.G("cve") != true || rec.G("nvd") != true || rec.G("osv") != true {
			t.Errorf("%s: cve, nvd and osv should all exist: %v %v %v", c.name, rec.G("cve"), rec.G("nvd"), rec.G("osv"))
		}
		if got := rec.G("kernel"); got != c.wantKernel {
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
