package scan

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/corefense-security/trowl/internal/llm"
	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/corefense-security/trowl/internal/sbom"
	"github.com/corefense-security/trowl/internal/unpack"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOfflineNote(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kev, epss *pyjson.Obj
		missing   int
		want      string
	}{
		{"dated", pyjson.O("released", "2026-11-21T12:00:00Z"), pyjson.O("date", "2026-11-20"), 3,
			"--no-network: KEV from 2026-11-21; EPSS from 2026-11-20; 3 CVEs without cached advisory links"},
		{"missing", nil, nil, 0, "--no-network: KEV cache unavailable; EPSS cache unavailable"},
		{"unknown dates", pyjson.New(), pyjson.New(), 0, "--no-network: KEV cached (date unknown); EPSS cached (date unknown)"},
		{"short date", pyjson.O("released", "2026"), nil, 0, "--no-network: KEV from 2026; EPSS cache unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := offlineNote(tc.kev, tc.epss, tc.missing); got != tc.want {
				t.Errorf("notice = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOfflineRunMissingModel(t *testing.T) {
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("offline scan requested %s", r.URL)
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}, Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })
	dir := t.TempDir()
	root := filepath.Join(dir, "rootfs")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("image content"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := filepath.Join(dir, "llama-server")
	if err := os.WriteFile(server, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TROWL_LLAMA_SERVER", server)
	t.Setenv("TROWL_MODEL_FILE", "")
	cache := filepath.Join(dir, "cache")
	result, err := Run(&unpack.Unpacked{Rootfs: root, SourceFormat: "directory"}, root,
		Options{CacheDir: cache, Links: "open", Model: llm.DefaultModel, Network: false})
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 1 || result.Report.G("overview") != nil {
		t.Errorf("scan did not finish without a summary: %+v", result)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Errorf("offline scan created the cache: %v", err)
	}
}

func TestOfflineEnrichment(t *testing.T) {
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("offline scan requested %s", r.URL)
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}, Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })
	dir := t.TempDir()
	var zipped bytes.Buffer
	w := gzip.NewWriter(&zipped)
	fmt.Fprintln(w, "#model_version:v1,score_date:2026-11-21\ncve,epss,percentile\nCVE-2026-1,0.75,0.99")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	cache := map[string][]byte{
		"kev.json":      []byte(`{"catalogVersion":"2026.11.21","vulnerabilities":[{"cveID":"CVE-2026-1"}]}`),
		"epss.csv.gz":   zipped.Bytes(),
		"links-v2.json": []byte(`{"CVE-2026-1":{"nvd":true,"t":1},"CVE-2026-2":{"nvd":true,"t":1}}`),
	}
	stamp := time.Now().Add(-30 * 24 * time.Hour)
	for name, raw := range cache {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(t.TempDir(), "bom.json")
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"application","bom-ref":"app","name":"app","version":"1.0","cpe":"cpe:2.3:a:vendor:app:1.0:*:*:*:*:*:*:*"}],"vulnerabilities":[{"id":"CVE-2026-1","analysis":{"state":"exploitable"},"affects":[{"ref":"app"}]},{"id":"CVE-2026-2","analysis":{"state":"resolved"},"affects":[{"ref":"app"}]},{"id":"CVE-2026-3","analysis":{"state":"resolved"},"affects":[{"ref":"app"}]}]}`
	if err := os.WriteFile(file, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"open", "all", "none"} {
		t.Run(mode, func(t *testing.T) {
			sb, err := sbom.Load(file)
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := cveSection(sb, &sbom.Status{}, t.TempDir(), Options{CacheDir: dir, Links: mode, Network: false}, nil)
			if err != nil {
				t.Fatal(err)
			}
			rows := result.G("rows").([]any)
			if len(rows) != 3 {
				t.Fatalf("rows = %d, want 3", len(rows))
			}
			sources := result.G("sources").(*pyjson.Obj)
			wantMissing := any(0)
			if mode == "all" {
				wantMissing = 1
			} else if mode == "none" {
				wantMissing = nil
			}
			if sources.G("offline") != true || sources.G("links_missing") != wantMissing {
				t.Errorf("offline metadata = %s", pyjson.Default(sources))
			}
			for _, row := range rows {
				r := row.(*pyjson.Obj)
				if r.G("id") == "CVE-2026-1" && (r.G("kev") == nil || r.G("epss") == nil) {
					t.Error("cached KEV or EPSS missing from the report")
				}
				wantLink := r.G("id") != "CVE-2026-3" && (mode == "all" || mode == "open" && r.G("status") != "fixed")
				links, _ := r.G("links").([]any)
				if (len(links) > 0) != wantLink {
					t.Errorf("%s: links = %v", r.G("id"), links)
				}
			}
		})
	}
	for name, raw := range cache {
		path := filepath.Join(dir, name)
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("cache %s changed: %v", name, err)
		}
		info, err := os.Stat(path)
		if err != nil || !info.ModTime().Equal(stamp) {
			t.Errorf("cache %s timestamp changed: %v", name, err)
		}
	}
}
