// Package kconfig checks the kernel configuration against the baseline lists in baseline/.
//
// The config is read from the image itself. It comes from /boot/config-*, or else from the copy
// the kernel embeds in its own image when built with CONFIG_IKCONFIG (the same data
// extract-ikconfig recovers). A config or kernel tree given on the command line is only used when
// the image has neither.
//
// The lists decide what is expected, and this package only compares. An option absent from the
// config is not the same as "is not set", because Kconfig drops options whose dependencies are
// off. So for an option expected on, absence is reported as "missing". It is neither passed nor
// silently ignored.
package kconfig

import (
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/ulikunitz/xz"
	"gopkg.in/yaml.v3"
)

//go:embed baseline
var baselineFS embed.FS

var Subsystems = []string{"security", "fs", "mm", "net", "module"} // module = kernel/module
var Buckets = []string{"harden", "attack_surface"}

var (
	ikcfgSt, ikcfgEd = []byte("IKCFG_ST"), []byte("IKCFG_ED")
	kernelImages     = []string{"vmlinuz*", "bzImage*", "zImage*", "Image*", "vmlinux*", "uImage*", "fitImage*"}
	header           = regexp.MustCompile(`(?m)^# Linux/(\S+) (\d+\.\d+(?:\.\d+)?)\S* Kernel Configuration`)
	lineRe           = regexp.MustCompile(`^(?:CONFIG_(\w+)=(.*)|# CONFIG_(\w+) is not set)$`)
	verRe            = regexp.MustCompile(`\d+`)
	modVerRe         = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?`)
	// Kconfig's arch name -> the names the lists use
	archAliases = map[string]string{"x86_64": "x86", "i386": "x86", "x86": "x86", "arm64": "arm64",
		"aarch64": "arm64", "arm": "arm", "riscv": "riscv", "powerpc": "powerpc", "mips": "mips"}
)

const maxKernelBytes = 256 * 1024 * 1024

// Entry is one baseline or team-policy line.
type Entry map[string]any

func (e Entry) str(k string) string {
	if v, ok := e[k]; ok && v != nil {
		return pyStr(v)
	}
	return ""
}

func LoadBaseline() []Entry {
	var out []Entry
	for _, sub := range Subsystems {
		for _, bucket := range Buckets {
			raw, err := baselineFS.ReadFile("baseline/" + sub + "/" + bucket + ".yaml")
			if err != nil {
				continue
			}
			var items []map[string]any
			yaml.Unmarshal(raw, &items)
			for _, it := range items {
				e := Entry{}
				for k, v := range it {
					e[k] = v
				}
				e["subsystem"], e["bucket"] = sub, bucket
				out = append(out, e)
			}
		}
	}
	return out
}

func ikconfig(blob []byte) (string, bool) {
	i := bytes.Index(blob, ikcfgSt)
	if i < 0 {
		return "", false
	}
	j := bytes.Index(blob[i:], ikcfgEd)
	data := blob[i+len(ikcfgSt):]
	if j > 0 {
		data = blob[i+len(ikcfgSt) : i+j]
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", false
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return "", false
	}
	return py.DecodeReplace(out), true
}

// payloads yields decompressed candidates inside a compressed kernel image (bzImage, zImage, vmlinuz).
func payloads(blob []byte, yield func([]byte) bool) {
	formats := []struct {
		magic []byte
		kind  string
	}{{[]byte{0x1f, 0x8b, 0x08}, "gzip"}, {[]byte("\xfd7zXZ\x00"), "xz"}, {[]byte{0x28, 0xb5, 0x2f, 0xfd}, "zstd"}}
	for _, f := range formats {
		start := 0
		for n := 0; n < 8; n++ { // a few candidates per format is plenty, since real payloads come first
			off := bytes.Index(blob[start:], f.magic)
			if off < 0 {
				break
			}
			off += start
			start = off + 1
			var out []byte
			var ok bool
			switch f.kind {
			case "gzip":
				out, ok = inflate(func() (io.Reader, error) {
					r, err := gzip.NewReader(bytes.NewReader(blob[off:]))
					if r != nil {
						r.Multistream(false)
					}
					return r, err
				})
			case "xz":
				out, ok = inflate(func() (io.Reader, error) { return xz.NewReader(bytes.NewReader(blob[off:])) })
			case "zstd":
				if _, err := exec.LookPath("zstd"); err == nil {
					cmd := exec.Command("zstd", "-dcq")
					cmd.Stdin = bytes.NewReader(blob[off:])
					var stdout bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Run()
					out, ok = stdout.Bytes(), true
				}
			}
			if ok && !yield(out) {
				return
			}
		}
	}
}

// inflate reads up to maxKernelBytes. A stream cut short still yields what was decoded, as
// Python's decompressobj does.
func inflate(open func() (io.Reader, error)) ([]byte, bool) {
	r, err := open()
	if err != nil {
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(r, maxKernelBytes))
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, false
	}
	return out, true
}

func fromKernelImage(path string) (string, bool) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	if len(blob) > maxKernelBytes {
		blob = blob[:maxKernelBytes]
	}
	if t, ok := ikconfig(blob); ok && t != "" {
		return t, true
	}
	var text string
	payloads(blob, func(p []byte) bool {
		if t, ok := ikconfig(p); ok && t != "" {
			text = t
			return false
		}
		return true
	})
	return text, text != ""
}

func globSorted(dir, pattern string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, pattern))
	py.SortPaths(m)
	return m
}

func FindConfig(rootfs, kernelConfig, kernelSrc string) (string, *pyjson.Obj) {
	boot := py.InRoot(rootfs, "boot")
	if py.IsDir(boot) {
		configs := globSorted(boot, "config-*")
		for i := len(configs) - 1; i >= 0; i-- {
			name := "/boot/" + filepath.Base(configs[i])
			if c := py.InRoot(rootfs, name); py.IsFile(c) {
				raw, _ := os.ReadFile(c)
				return py.DecodeReplace(raw), pyjson.O("kind", "image", "path", name)
			}
		}
		for _, pattern := range kernelImages {
			for _, k := range globSorted(boot, pattern) {
				if py.IsFile(k) && !py.IsSymlink(k) {
					if text, ok := fromKernelImage(k); ok {
						return text, pyjson.O("kind", "embedded", "path", "/boot/"+filepath.Base(k))
					}
				}
			}
		}
	}
	if kernelConfig != "" && py.IsFile(kernelConfig) {
		raw, _ := os.ReadFile(kernelConfig)
		return py.DecodeReplace(raw), pyjson.O("kind", "--kernel-config", "path", py.CleanPath(kernelConfig))
	}
	if kernelSrc != "" {
		for _, c := range []string{filepath.Join(kernelSrc, ".config"), filepath.Join(kernelSrc, "build", ".config")} {
			if py.IsFile(c) {
				raw, _ := os.ReadFile(c)
				return py.DecodeReplace(raw), pyjson.O("kind", "--kernel-src", "path", py.CleanPath(c))
			}
		}
	}
	return "", nil
}

// Config holds parsed option values: "y", "m", "n" (is not set) or the literal value.
type Config map[string]string

func Parse(text string) (Config, string, string) {
	values := Config{}
	for _, line := range py.SplitLines(text) {
		m := lineRe.FindStringSubmatch(py.Strip(line))
		if m == nil {
			continue
		}
		if m[1] != "" {
			values[m[1]] = strings.Trim(m[2], `"`)
		} else {
			values[m[3]] = "n"
		}
	}
	h := header.FindStringSubmatch(text)
	arch, version := "", ""
	if h != nil {
		arch = h[1]
		if a, ok := archAliases[h[1]]; ok {
			arch = a
		}
		version = h[2]
	}
	if arch == "" {
		if values["X86"] == "y" {
			arch = "x86"
		} else if values["ARM64"] == "y" {
			arch = "arm64"
		}
	}
	return values, arch, version
}

func ver(v string) []int {
	var out []int
	for i, s := range verRe.FindAllString(v, -1) {
		if i == 3 {
			break
		}
		n, _ := strconv.Atoi(s)
		out = append(out, n)
	}
	return out
}

func verLess(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func ModulesVersion(rootfs string) string {
	mods := py.InRoot(rootfs, "lib/modules")
	var names []string
	if py.IsDir(mods) {
		entries, _ := os.ReadDir(mods)
		for _, e := range entries {
			if py.IsDir(py.InRoot(rootfs, "lib/modules/"+e.Name())) {
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return modVerRe.FindString(names[len(names)-1])
}

type policy struct {
	accept map[string]map[string]any
	add    []Entry
}

func LoadPolicy(path string) (*policy, error) {
	p := &policy{accept: map[string]map[string]any{}}
	if path == "" {
		return p, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	accept, _ := doc["accept"].([]any)
	for _, item := range accept {
		a, _ := item.(map[string]any)
		if !truthy(a["reason"]) {
			return nil, fmt.Errorf("%s: accepted option %s needs a reason", py.CleanPath(path), pyStrOrNone(a["option"]))
		}
		p.accept[pyStr(a["option"])] = a
	}
	add, _ := doc["add"].([]any)
	for _, item := range add {
		a, _ := item.(map[string]any)
		e := Entry{}
		for k, v := range a {
			e[k] = v
		}
		if _, ok := e["subsystem"]; !ok {
			e["subsystem"] = "team"
		}
		if _, ok := e["bucket"]; !ok {
			e["bucket"] = "harden"
		}
		e["ref"] = "team policy"
		p.add = append(p.add, e)
	}
	return p, nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case int:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// pyStr mirrors str() for the scalar values YAML gives.
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(x)
	case float64:
		return pyjson.Float(x)
	case time.Time:
		if x.Hour() == 0 && x.Minute() == 0 && x.Second() == 0 && x.Nanosecond() == 0 {
			return x.Format("2006-01-02")
		}
		return x.Format("2006-01-02 15:04:05")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("'%s': %s", k, pyRepr(x[k])))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

func pyRepr(v any) string {
	if s, ok := v.(string); ok {
		return "'" + s + "'"
	}
	return pyStr(v)
}

func pyStrOrNone(v any) string { return pyStr(v) }

// jsonValue converts YAML values into report values.
func jsonValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		o := pyjson.New()
		for _, k := range keys {
			o.Set(k, jsonValue(x[k]))
		}
		return o
	case []any:
		out := make([]any, len(x))
		for i, y := range x {
			out[i] = jsonValue(y)
		}
		return out
	case time.Time:
		return pyStr(x)
	}
	return v
}

func judge(e Entry, values Config) (string, string) {
	actual, present := values[e.str("option")]
	expect := e["expect"]
	if m, ok := expect.(map[string]any); ok {
		if min, ok := m["min"]; ok {
			if !present || actual == "n" {
				return "missing", ""
			}
			n, err := strconv.ParseInt(actual, 0, 64)
			if err != nil {
				return "fail", "not a number"
			}
			want, _ := strconv.ParseInt(pyStr(min), 10, 64)
			if n >= want {
				return "pass", ""
			}
			return "fail", ""
		}
	}
	var want string
	switch x := expect.(type) {
	case bool:
		want = "n"
		if x {
			want = "y"
		}
	default:
		want = pyStr(expect)
	}
	if want == "n" {
		if !present || actual == "n" {
			return "pass", ""
		}
		return "fail", ""
	}
	if present && actual == want {
		return "pass", ""
	}
	if !present {
		return "missing", "not in this config: its dependencies are off, or the compiler lacks support"
	}
	if actual == "m" && want == "y" {
		return "fail", "built as a module"
	}
	return "fail", ""
}

func archList(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, pyStr(x))
		}
	}
	return out
}

// Check runs the config check and the module inventory.
func Check(rootfs, kernelConfig, kernelSrc, policyPath string) (*pyjson.Obj, []model.Finding, error) {
	text, source := FindConfig(rootfs, kernelConfig, kernelSrc)
	if source == nil {
		version := ModulesVersion(rootfs)
		return pyjson.O("source", nil, "version", version, "arch", "", "entries", []any{},
			"modules", ScanModules(rootfs, Config{}, version)), nil, nil
	}
	values, arch, version := Parse(text)
	if version == "" {
		version = ModulesVersion(rootfs)
	}
	pol, err := LoadPolicy(policyPath)
	if err != nil {
		return nil, nil, err
	}
	today := time.Now().Format("2006-01-02")

	entries := []any{}
	var findings []model.Finding
	for _, e := range append(LoadBaseline(), pol.add...) {
		if archs := archList(e["arch"]); len(archs) > 0 && arch != "" && !contains(archs, arch) {
			continue // the option doesn't exist on this architecture
		}
		option := e.str("option")
		expect := e["expect"]
		var expectOut any = jsonValue(expect)
		if b, ok := expect.(bool); ok {
			expectOut = "n"
			if b {
				expectOut = "y"
			}
		}
		var actual any
		if v, ok := values[option]; ok {
			actual = v
		}
		why, ref := e.str("why"), e.str("ref")
		if _, ok := e["why"]; !ok {
			why = ""
		}
		if _, ok := e["ref"]; !ok {
			ref = ""
		}
		row := pyjson.O("subsystem", e["subsystem"], "bucket", e["bucket"], "option", option, "expect", expectOut,
			"actual", actual, "why", why, "ref", ref, "note", "")
		if since := e["since"]; truthy(since) && version != "" && verLess(ver(version), ver(pyStr(since))) {
			row.Set("status", "na")
			row.Set("note", "added in Linux "+pyStr(since))
		} else {
			status, note := judge(e, values)
			row.Set("status", status)
			row.Set("note", note)
		}
		status := row.G("status").(string)
		if acc, ok := pol.accept[option]; ok && (status == "fail" || status == "missing") {
			expires := acc["expires"]
			if truthy(expires) && pyStr(expires) < today {
				row.Set("note", "policy acceptance expired "+pyStr(expires))
			} else {
				row.Set("status", "accepted")
				row.Set("note", jsonValue(acc["reason"]))
			}
		}
		entries = append(entries, row)
		if s := row.G("status").(string); s == "fail" || s == "missing" {
			exposed := row.G("bucket") == "attack_surface"
			check := "kernel.hardening"
			if exposed {
				check = "kernel.attack-surface"
			}
			shown := "missing"
			if a, ok := actual.(string); ok && a != "" {
				shown = a
			}
			ev := pyjson.New()
			for _, k := range []string{"subsystem", "bucket", "ref", "note"} {
				ev.Set(k, row.G(k))
			}
			findings = append(findings, model.Finding{Check: check,
				Title:  fmt.Sprintf("CONFIG_%s is %s, expected %s", option, shown, expectString(expectOut, expect)),
				Detail: why, Evidence: ev})
		}
	}

	modules := ScanModules(rootfs, values, version)
	if modules.G("mode") == "enforced" {
		for _, m := range modules.G("items").([]any) {
			if signed, ok := m.(*pyjson.Obj).G("signed").(bool); ok && !signed {
				findings = append(findings, model.Finding{Check: "kernel.unsigned-module",
					Path: m.(*pyjson.Obj).G("path").(string), Title: "Unsigned module will be refused by this kernel (MODULE_SIG_FORCE=y)"})
			}
		}
	}
	var pol2 any
	if policyPath != "" {
		pol2 = py.CleanPath(policyPath)
	}
	return pyjson.O("source", source, "version", version, "arch", arch, "entries", entries,
		"policy", pol2, "modules", modules), findings, nil
}

// expectString renders row["expect"] the way Python's f-string does. A dict prints as its repr.
func expectString(out any, raw any) string {
	if s, ok := out.(string); ok {
		return s
	}
	return pyStr(raw)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
