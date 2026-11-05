package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRefusesWhatIsNotAnSBOM(t *testing.T) {
	for name, text := range map[string]string{
		"plain text": "not json",
		"truncated":  `{"@graph": [{"type": "software_Pack`,
		"SPDX 2.3":   `{"spdxVersion": "SPDX-2.3", "packages": []}`,
	} {
		p := filepath.Join(t.TempDir(), "sbom.json")
		os.WriteFile(p, []byte(text), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}
