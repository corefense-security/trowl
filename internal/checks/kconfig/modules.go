package kconfig

// Kernel modules shipped in the image and whether each carries a signature.
//
// A signed module ends with a `struct module_signature` followed by the magic string the kernel's
// sign-file tool appends. Compressed modules (.ko.xz/.gz/.zst) are signed before compression, so they
// are inflated first. Whether the kernel refuses unsigned modules is a config question
// (MODULE_SIG / MODULE_SIG_FORCE), answered from the same config the Kernel config check reads.

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/ulikunitz/xz"
)

var sigMagic = []byte("~Module signature appended~\n")
var idTypes = map[byte]string{0: "PGP", 1: "X.509", 2: "PKCS#7"}
var moduleSuffixes = []string{".ko", ".ko.xz", ".ko.gz", ".ko.zst"}

func readModule(path string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	name := filepath.Base(path)
	switch {
	case strings.HasSuffix(name, ".xz"):
		r, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		out, err := io.ReadAll(r)
		return out, err == nil
	case strings.HasSuffix(name, ".gz"):
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		out, err := io.ReadAll(r)
		return out, err == nil
	case strings.HasSuffix(name, ".zst"):
		if _, err := exec.LookPath("zstd"); err != nil {
			return nil, false
		}
		cmd := exec.Command("zstd", "-dcq")
		cmd.Stdin = bytes.NewReader(data)
		out, err := cmd.Output()
		return out, err == nil
	}
	return data, true
}

func signature(data []byte) *pyjson.Obj {
	n := len(sigMagic)
	if !bytes.HasSuffix(data, sigMagic) || len(data) < n+12 {
		return nil
	}
	s := data[len(data)-n-12 : len(data)-n]
	idType := s[2]
	sigLen := binary.BigEndian.Uint32(s[8:12])
	if sigLen == 0 || int(sigLen) > len(data) {
		return nil
	}
	t, ok := idTypes[idType]
	if !ok {
		t = fmt.Sprintf("type %d", idType)
	}
	return pyjson.O("type", t, "length", int(sigLen))
}

func modinfo(data []byte) map[string]string {
	info := map[string]string{}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return info
	}
	sec := f.Section(".modinfo")
	if sec == nil {
		return info
	}
	raw, err := sec.Data()
	if err != nil {
		return info
	}
	for _, item := range bytes.Split(raw, []byte{0}) {
		k, v, found := strings.Cut(py.DecodeReplace(item), "=")
		if _, seen := info[k]; found && !seen {
			info[k] = v
		}
	}
	return info
}

// SigningMode is enforced | checked | off | no-modules | unknown.
func SigningMode(config Config) string {
	if len(config) == 0 {
		return "unknown"
	}
	if config["MODULES"] != "y" {
		return "no-modules"
	}
	if config["MODULE_SIG_FORCE"] == "y" {
		return "enforced"
	}
	if config["MODULE_SIG"] == "y" {
		return "checked"
	}
	return "off"
}

// rglob lists files under root like Path.rglob("*"). It doesn't descend into symlinked
// directories, but keeps symlinks to files.
func rglob(root string) []string {
	var out []string
	var walk func(dir string)
	walk = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			out = append(out, p)
			if py.IsDir(p) && e.Type()&os.ModeSymlink == 0 {
				walk(p)
			}
		}
	}
	walk(root)
	return out
}

func hasModuleSuffix(name string) bool {
	for _, s := range moduleSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func ScanModules(rootfs string, config Config, kernelVersion string) *pyjson.Obj {
	root := py.InRoot(rootfs, "lib/modules")
	items := []any{}
	var paths []string
	if py.IsDir(root) {
		for _, p := range rglob(root) {
			if py.IsFile(p) && !py.IsSymlink(p) && hasModuleSuffix(filepath.Base(p)) {
				paths = append(paths, p)
			}
		}
	}
	py.SortPaths(paths)
	for _, path := range paths {
		rel, _ := filepath.Rel(root, path)
		rel = "/lib/modules/" + rel
		fi, _ := os.Stat(path)
		base := filepath.Base(path)
		stem := strings.SplitN(base, ".ko", 2)[0]
		data, ok := readModule(path)
		if !ok {
			items = append(items, pyjson.O("path", rel, "name", stem, "size", int(fi.Size()), "signed", nil,
				"signature", nil, "vermagic", "", "license", "", "package", ""))
			continue
		}
		info := modinfo(data)
		sig := signature(data)
		vermagic := info["vermagic"]
		name := info["name"]
		if name == "" {
			name = stem
		}
		var sigOut any
		if sig != nil {
			sigOut = sig
		}
		items = append(items, pyjson.O(
			"path", rel, "name", name, "size", int(fi.Size()),
			"compressed", !strings.HasSuffix(base, ".ko"), "signed", sig != nil, "signature", sigOut,
			"vermagic", vermagic,
			"vermagic_match", kernelVersion != "" && strings.HasPrefix(strings.SplitN(vermagic, " ", 2)[0], kernelVersion),
			"license", info["license"], "package", ""))
	}
	cfg := pyjson.New()
	for _, k := range []string{"MODULES", "MODULE_SIG", "MODULE_SIG_FORCE", "MODULE_SIG_ALL"} {
		if v, ok := config[k]; ok {
			cfg.Set(k, v)
		} else {
			cfg.Set(k, nil)
		}
	}
	return pyjson.O("mode", SigningMode(config), "config", cfg, "items", items)
}
