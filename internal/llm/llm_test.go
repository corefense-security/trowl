package llm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOfflineModelCache(t *testing.T) {
	t.Setenv("TROWL_MODEL_FILE", "")
	old := http.DefaultTransport
	requests := 0
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}, Request: r}, nil
	})
	t.Cleanup(func() {
		http.DefaultTransport = old
		if requests != 0 {
			t.Errorf("offline model loader made %d HTTP requests", requests)
		}
	})
	cache := filepath.Join(t.TempDir(), "cache")
	if got := ensureModel(DefaultModel, cache, false); got != "" {
		t.Fatalf("missing model = %q", got)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("offline loader created the cache: %v", err)
	}
	path := filepath.Join(cache, "models", Models[DefaultModel].File)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("local model"), 0o444); err != nil {
		t.Fatal(err)
	}
	if got := ensureModel(DefaultModel, cache, false); got != path {
		t.Fatalf("cached model = %q, want %q", got, path)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "local model" {
		t.Errorf("model changed: %q, %v", got, err)
	}
}

func TestOnlineModelDownload(t *testing.T) {
	t.Setenv("TROWL_MODEL_FILE", "")
	raw := []byte("test model weights")
	oldModel := Models[DefaultModel]
	m := oldModel
	m.URL, m.Sha256 = "https://model.test/weights", fmt.Sprintf("%x", sha256.Sum256(raw))
	Models[DefaultModel] = m
	old := http.DefaultTransport
	requests := 0
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}, Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport, Models[DefaultModel] = old, oldModel })
	cache := t.TempDir()
	want := filepath.Join(cache, "models", m.File)
	if got := ensureModel(DefaultModel, cache, true); got != want {
		t.Fatalf("downloaded model = %q, want %q", got, want)
	}
	if got, err := os.ReadFile(want); err != nil || !bytes.Equal(got, raw) || requests != 1 {
		t.Errorf("model = %q, error = %v, requests = %d", got, err, requests)
	}
}

func TestOfflineLocalInference(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected inference path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"choices":[{"message":{"content":"local summary"}}]}`)
	}))
	defer server.Close()
	r := NewRunner(DefaultModel, t.TempDir(), false)
	r.url = server.URL
	if got := r.complete("system", "facts", 10); got != "local summary" {
		t.Errorf("local summary = %q", got)
	}
}

func TestBullets(t *testing.T) {
	reply := "Here is the assessment:\n\n- **Hardening:** 82% of binaries lack a protection.\n* Second point\n• Third point\n4. Fourth point\n5) Fifth point\n- Sixth point\n- Seventh point\n- Eighth point\n"
	want := []string{"82% of binaries lack a protection.", "Second point", "Third point", "Fourth point", "Fifth point"}
	if got := bullets(reply); !reflect.DeepEqual(got, want) {
		t.Fatalf("bullets() = %q, want %q", got, want)
	}
	labelled := "- **Systemic hardening weaknesses:** indirect calls are unprotected\n- Vulnerability triage implications: curl needs an update"
	want = []string{"indirect calls are unprotected", "curl needs an update"}
	if got := bullets(labelled); !reflect.DeepEqual(got, want) {
		t.Fatalf("bullets() = %q, want %q", got, want)
	}
	want = []string{"first point", "second point"}
	if got := bullets("Assessment:\n\nfirst point\nsecond point\n"); !reflect.DeepEqual(got, want) {
		t.Fatalf("bullets() = %q, want %q", got, want)
	}
}

// A label is shown to users, so it must be the model's published name, as in its file name.
func TestLabelsAreModelNames(t *testing.T) {
	for id, m := range Models {
		if want := strings.TrimSuffix(m.File, "-Q4_K_M.gguf"); m.Label != want {
			t.Errorf("%s: label %q, want %q", id, m.Label, want)
		}
	}
}

// TROWL_MODEL_FILE is used as is, so nothing is downloaded.
func TestModelFileFromEnv(t *testing.T) {
	file := filepath.Join(t.TempDir(), "model.gguf")
	os.WriteFile(file, []byte("gguf"), 0o644)
	t.Setenv("TROWL_MODEL_FILE", file)
	if got := ensureModel(DefaultModel, t.TempDir(), false); got != file {
		t.Errorf("got %q, want %q", got, file)
	}
	t.Setenv("TROWL_MODEL_FILE", filepath.Join(t.TempDir(), "missing.gguf"))
	if got := ensureModel(DefaultModel, t.TempDir(), false); got != "" {
		t.Errorf("missing file: got %q", got)
	}
}

// A server that dies is noticed at once rather than after the 5 minute wait.
func TestServerThatExitsIsNoticed(t *testing.T) {
	dir := t.TempDir()
	server := filepath.Join(dir, "llama-server")
	os.WriteFile(server, []byte("#!/bin/sh\necho 'libssl.so.3: version not found' >&2\nexit 1\n"), 0o755)
	model := filepath.Join(dir, "model.gguf")
	os.WriteFile(model, []byte("gguf"), 0o644)
	t.Setenv("TROWL_LLAMA_SERVER", server)
	t.Setenv("TROWL_MODEL_FILE", model)
	r := NewRunner(DefaultModel, dir, false)
	start := time.Now()
	if r.start() {
		t.Fatal("started")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
	if !strings.Contains(r.stderr.last(5), "libssl") {
		t.Errorf("stderr %q", r.stderr.last(5))
	}
	r.Close()
}
