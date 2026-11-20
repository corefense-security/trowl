package llm

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
	if got := ensureModel(DefaultModel, t.TempDir()); got != file {
		t.Errorf("got %q, want %q", got, file)
	}
	t.Setenv("TROWL_MODEL_FILE", filepath.Join(t.TempDir(), "missing.gguf"))
	if got := ensureModel(DefaultModel, t.TempDir()); got != "" {
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
	r := NewRunner(DefaultModel, dir)
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
