package py

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInRoot(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	for link, target := range map[string]string{
		"lib": "usr/lib", "abs": "/usr/lib", "up": "../../../usr/lib", "host": "/etc", "loop": "loop",
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	for p, want := range map[string]string{
		"lib/x":   "usr/lib/x",
		"abs/x":   "usr/lib/x",
		"up/x":    "usr/lib/x",
		"/lib/x":  "usr/lib/x",
		"../../x": "x",
		"host":    "etc",
	} {
		if got := InRoot(root, p); got != filepath.Join(root, want) {
			t.Errorf("%s: got %s, want %s", p, got, filepath.Join(root, want))
		}
	}
	if _, err := os.Stat(InRoot(root, "loop")); err == nil {
		t.Error("a link loop should not resolve")
	}
}
