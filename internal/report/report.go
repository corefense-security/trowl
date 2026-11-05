// Package report writes the report as JSON and as a single self-contained HTML file (the bundled UI).
package report

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/corefense-security/trowl/internal/pyjson"
)

// The UI is built by `npm run build` in ui/ into ui/index.html here, then compiled into the binary.
//
//go:embed all:ui
var uiFS embed.FS

const placeholder = "__TROWL_REPORT__"

// slot matches the data element itself, so the string appearing elsewhere in the bundle can't be hit.
const slot = `<script id="trowl-report" type="application/json">` + placeholder + `</script>`

func WriteJSON(r *pyjson.Obj, path string) error {
	return writeFile(path, []byte(pyjson.Indent1(r)))
}

// writeFile writes to a temporary file next to path and renames it into place. A rename only
// needs the folder to be writable, so it replaces a report left by another user (a container
// running as a different uid), and a failed write never leaves a half-written report behind.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// WriteHTML embeds the report into the built UI. It returns false if the UI wasn't built.
func WriteHTML(r *pyjson.Obj, path string) (bool, error) {
	out, ok := render([]byte(pyjson.Compact(r)), gzip.BestCompression)
	if !ok {
		return false, nil
	}
	return true, writeFile(path, out)
}

// RenderJSON builds the dashboard page for a report.json, with the UI built into this binary.
// It lets a viewer show the current UI over an existing scan, so a UI change doesn't need a
// rescan. ok is false when the UI wasn't built or the file isn't JSON.
func RenderJSON(raw []byte) ([]byte, bool) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil { // keeps key order: it only drops whitespace
		return nil, false
	}
	return render(compact.Bytes(), gzip.BestSpeed)
}

// render puts the compact report JSON into the built UI's data slot.
func render(compactJSON []byte, level int) ([]byte, bool) {
	tmpl, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		return nil, false
	}
	template := string(tmpl)
	if !strings.Contains(template, slot) {
		return nil, false
	}
	// Gzip + base64 keeps the page a fraction of the JSON size (the CVE list dominates); the
	// viewer inflates it with the browser's DecompressionStream. Base64 has no "</" in it.
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, level)
	zw.Write(compactJSON)
	zw.Close()
	payload := "gz:" + base64.StdEncoding.EncodeToString(buf.Bytes())
	return []byte(strings.Replace(template, slot, strings.Replace(slot, placeholder, payload, 1), 1)), true
}
