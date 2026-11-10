// Command trowl: static analysis of embedded Linux root filesystems.
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/corefense-security/trowl/internal/llm"
	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/report"
	"github.com/corefense-security/trowl/internal/scan"
	"github.com/corefense-security/trowl/internal/status"
	"github.com/corefense-security/trowl/internal/unpack"
)

// opt describes one command-line option.
type opt struct {
	names   []string
	value   bool // takes a value
	def     string
	choices []string
	help    string
}

type command struct {
	name, help  string
	positionals []string // "?" suffix marks an optional positional
	posDefault  map[string]string
	opts        []opt
	run         func(a args) int
}

type args map[string]string

func (a args) flag(name string) bool { return a[name] == "true" }

func defaultHost() string {
	// The container image sets TROWL_HOST=0.0.0.0 so a published port reaches the server.
	if h := os.Getenv("TROWL_HOST"); h != "" {
		return h
	}
	return "127.0.0.1"
}

func defaultCache() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "trowl")
}

func commands() []*command {
	return []*command{
		{
			name: "scan", help: "analyse an image and write a static dashboard (index.html) plus report.json",
			positionals: []string{"image"},
			opts: []opt{
				{names: []string{"--sbom"}, value: true, help: "SPDX 3.0 JSON-LD SBOM for the image"},
				{names: []string{"-o", "--output"}, value: true, def: "trowl-report", help: "output directory"},
				{names: []string{"--fail-on"}, value: true, choices: model.Severities,
					help: "exit 1 if any finding is at or above this severity (for CI)"},
				{names: []string{"--kernel-config"}, value: true, help: "kernel .config to check when the image carries none " +
					"(/boot/config-* or a config embedded in the kernel image)"},
				{names: []string{"--kernel-src"}, value: true, help: "kernel build tree whose .config to use when the image carries none"},
				{names: []string{"--kernel-tree"}, value: true, help: "source tree of the image's kernel, checked out at its version. " +
					"Kernel CVEs get a VEX status from the config gates of the files their CNA record names"},
				{names: []string{"--kernel-policy"}, value: true, help: "YAML with team overrides: accept (with a reason) or add options"},
				{names: []string{"--no-network"}, help: "don't fetch CISA KEV / EPSS or check advisory links"},
				{names: []string{"--links"}, value: true, def: "open", choices: []string{"open", "all", "none"},
					help: "which CVEs get checked advisory links: not-fixed ones (default), all, or none"},
				{names: []string{"--model"}, value: true, def: llm.DefaultModel, choices: llm.ModelNames(),
					help: "local LLM that writes the Overview summary; downloaded into the cache on first use (default: " + llm.DefaultModel + ")"},
				{names: []string{"--cache-dir"}, value: true, def: defaultCache(),
					help: "where NVD data, the model, KEV, EPSS and link results are cached; created if missing. trowl needs write " +
						"permission to it, or the scan runs uncached (default: " + defaultCache() + ")"},
				{names: []string{"--workdir"}, value: true, help: "unpack here instead of a temp dir (kept afterwards)"},
				{names: []string{"--keep"}, help: "keep the temp unpack dir"},
			},
			run: cmdScan,
		},
		{
			name: "unpack", help: "only unpack an image to a directory",
			positionals: []string{"image", "dest"},
			run:         cmdUnpack,
		},
		{
			name: "view", help: "preview a report folder locally (no caching, so rescans show on reload)",
			positionals: []string{"directory?"}, posDefault: map[string]string{"directory": "trowl-report"},
			opts: []opt{
				{names: []string{"--port"}, value: true, def: "8765"},
				{names: []string{"--host"}, value: true, def: defaultHost()},
			},
			run: cmdView,
		},
	}
}

func usage() string {
	return "usage: trowl [-h] [--version] {scan,unpack,view} ..."
}

func fail(cmd, msg string) int {
	prog := "trowl"
	if cmd != "" {
		prog += " " + cmd
	}
	fmt.Fprintf(os.Stderr, "%s\n%s: error: %s\n", usage(), prog, msg)
	return 2
}

func printHelp(c *command) {
	fmt.Printf("usage: trowl %s [options] %s\n\n%s\n", c.name, strings.Join(c.positionals, " "), c.help)
	if len(c.opts) > 0 {
		fmt.Println("\noptions:")
		for _, o := range c.opts {
			fmt.Printf("  %-22s %s\n", strings.Join(o.names, ", "), o.help)
		}
	}
}

func parse(c *command, argv []string) (args, int, bool) {
	a := args{}
	for _, o := range c.opts {
		key := strings.TrimLeft(o.names[len(o.names)-1], "-")
		if o.value {
			a[key] = o.def
		}
	}
	var pos []string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "-h" || arg == "--help" {
			printHelp(c)
			return nil, 0, false
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			pos = append(pos, arg)
			continue
		}
		name, val, hasVal := strings.Cut(arg, "=")
		var match *opt
		for j := range c.opts {
			for _, n := range c.opts[j].names {
				if n == name {
					match = &c.opts[j]
				}
			}
		}
		if match == nil {
			return nil, fail(c.name, "unrecognized arguments: "+arg), false
		}
		key := strings.TrimLeft(match.names[len(match.names)-1], "-")
		if !match.value {
			a[key] = "true"
			continue
		}
		if !hasVal {
			if i+1 >= len(argv) {
				return nil, fail(c.name, fmt.Sprintf("argument %s: expected one argument", strings.Join(match.names, "/"))), false
			}
			i++
			val = argv[i]
		}
		if len(match.choices) > 0 && !contains(match.choices, val) {
			return nil, fail(c.name, fmt.Sprintf("argument %s: invalid choice: '%s' (choose from %s)",
				strings.Join(match.names, "/"), val, quoteList(match.choices))), false
		}
		a[key] = val
	}
	for i, p := range c.positionals {
		name := strings.TrimSuffix(p, "?")
		switch {
		case i < len(pos):
			a[name] = pos[i]
		case strings.HasSuffix(p, "?"):
			a[name] = c.posDefault[name]
		default:
			var missing []string
			for _, q := range c.positionals[i:] {
				missing = append(missing, q)
			}
			return nil, fail(c.name, "the following arguments are required: "+strings.Join(missing, ", ")), false
		}
	}
	if len(pos) > len(c.positionals) {
		return nil, fail(c.name, "unrecognized arguments: "+strings.Join(pos[len(c.positionals):], " ")), false
	}
	if p, ok := a["port"]; ok {
		if _, err := strconv.Atoi(p); err != nil {
			return nil, fail(c.name, fmt.Sprintf("argument --port: invalid int value: '%s'", p)), false
		}
	}
	return a, 0, true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = "'" + x + "'"
	}
	return strings.Join(q, ", ")
}

// writable creates dir if needed and checks that files can be created in it.
func writable(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".trowl-write-test-*")
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(f.Name())
}

// joinPath mirrors str(Path(dir) / name).
func joinPath(dir, name string) string {
	d := py.CleanPath(dir)
	if d == "." {
		return name
	}
	if strings.HasSuffix(d, "/") {
		return d + name
	}
	return d + "/" + name
}

// scanBanner lists what the scan will look at, so a log starts with the run's inputs.
func scanBanner(a args) {
	orNone := func(v, none string) string {
		if v == "" {
			return none
		}
		return py.CleanPath(v)
	}
	kernel := "from the image"
	for _, fallback := range []string{a["kernel-config"], a["kernel-src"]} {
		if fallback != "" {
			kernel += ", else " + py.CleanPath(fallback)
		}
	}
	network := "on"
	if a.flag("no-network") {
		network = "off"
	}
	rows := [][2]string{
		{"target", py.CleanPath(a["image"])},
		{"sbom", orNone(a["sbom"], "not supplied")},
		{"kernel", kernel},
	}
	if a["kernel-tree"] != "" {
		rows = append(rows, [2]string{"tree", py.CleanPath(a["kernel-tree"])})
	}
	if a["kernel-policy"] != "" {
		rows = append(rows, [2]string{"policy", py.CleanPath(a["kernel-policy"])})
	}
	rows = append(rows, [2]string{"network", network}, [2]string{"model", llm.Models[a["model"]].Label}, [2]string{"output", py.CleanPath(a["output"])})
	status.Banner("trowl "+model.Version, rows...)
}

func cmdScan(a args) int {
	scanBanner(a)
	out := a["output"]
	// Fail before the scan, not after it, when the report can't be saved (in a container this is
	// usually a mounted folder the container's user may not write to).
	if err := writable(out); err != nil {
		fmt.Fprintf(os.Stderr, "trowl: can't write the report to %s: %v\n", out, err)
		return 1
	}
	work := a["workdir"]
	if work == "" {
		var err error
		if work, err = os.MkdirTemp("", "trowl-"); err != nil {
			fmt.Fprintf(os.Stderr, "trowl: %v\n", err)
			return 1
		}
	}
	// NVD matching reads what was saved in the cache, so one that can't be written would quietly
	// drop CVEs from the report: keep this run's data with the unpacked image instead. With
	// --no-network nothing is saved, so a read-only cache is fine.
	cache := a["cache-dir"]
	if cache != "" && !a.flag("no-network") {
		if err := writable(cache); err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				err = pathErr.Err // it already names the path, which the message gives
			}
			status.Warn("can't write the cache to %s (%v); this run won't be cached", cache, err)
			cache = filepath.Join(work, "cache")
		}
	}
	modelName := a["model"]
	started := time.Now()
	res, code := func() (*scan.Result, int) {
		defer func() {
			if a["workdir"] == "" && !a.flag("keep") {
				os.RemoveAll(work)
			}
		}()
		st := status.Start("unpacking filesystem")
		u, err := unpack.Unpack(a["image"], work)
		if err != nil {
			st.Fail("")
			var ue *unpack.Error
			if errors.As(err, &ue) {
				fmt.Fprintf(os.Stderr, "trowl: %v\n", err)
				return nil, 2
			}
			fmt.Fprintf(os.Stderr, "trowl: %v\n", err)
			return nil, 1
		}
		st.Ok(u.SourceFormat)
		res, err := scan.Run(u, a["image"], scan.Options{
			SBOM: a["sbom"], Network: !a.flag("no-network"), CacheDir: cache, Links: a["links"],
			Model: modelName, KernelConfig: a["kernel-config"], KernelSrc: a["kernel-src"], KernelTree: a["kernel-tree"], KernelPolicy: a["kernel-policy"],
			Started: started,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "trowl: %v\n", err)
			return nil, 1
		}
		return res, 0
	}()
	if res == nil {
		return code
	}

	jsonPath, htmlPath := joinPath(out, "report.json"), joinPath(out, "index.html")
	st := status.Start("writing report")
	if err := report.WriteJSON(res.Report, filepath.Join(out, "report.json")); err != nil {
		st.Fail("")
		status.Warn("%v", err)
		return 1
	}
	html, err := report.WriteHTML(res.Report, filepath.Join(out, "index.html"))
	if err != nil {
		st.Fail("")
		status.Warn("%v", err)
		return 1
	}
	if html {
		st.Ok("")
	} else {
		st.Fail("dashboard UI not built")
	}

	fmt.Fprintln(os.Stderr)
	fmt.Printf("trowl %s: %d files (%s), %d ELF\n", model.Version, res.Files, res.Format, res.Binaries)
	var parts []string
	for i := len(model.Severities) - 1; i >= 0; i-- {
		s := model.Severities[i]
		parts = append(parts, fmt.Sprintf("%d %s", res.Counts.Get(s), s))
	}
	fmt.Println("findings: " + strings.Join(parts, ", "))
	if res.SbomCounts != nil {
		var kv []string
		for _, k := range res.SbomCounts.Keys() {
			kv = append(kv, fmt.Sprintf("%s=%d", k, res.SbomCounts.G(k)))
		}
		fmt.Println("sbom: " + strings.Join(kv, ", "))
	}
	if html {
		fmt.Printf("wrote %s and %s (static dashboard)\n", jsonPath, htmlPath)
	} else {
		fmt.Printf("wrote %s (UI not built: no index.html)\n", jsonPath)
	}

	exit := 0
	if f := a["fail-on"]; f != "" {
		threshold := model.SeverityRank(f)
		over := 0
		for _, fd := range res.Findings {
			if model.SeverityRank(fd.Severity) >= threshold {
				over++
			}
		}
		if over > 0 {
			status.Warn("failing: %d finding(s) at or above %s (--fail-on)", over, f)
			exit = 1
		}
	}
	return exit
}

func cmdUnpack(a args) int {
	u, err := unpack.Unpack(a["image"], a["dest"])
	if err != nil {
		fmt.Fprintf(os.Stderr, "trowl: %v\n", err)
		var ue *unpack.Error
		if errors.As(err, &ue) {
			return 2
		}
		return 1
	}
	fmt.Printf("%s: rootfs at %s\n", u.SourceFormat, py.CleanPath(u.Rootfs))
	for _, n := range u.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	return 0
}

func cmdView(a args) int {
	dir := a["directory"]
	if !py.IsFile(filepath.Join(dir, "index.html")) {
		fmt.Fprintf(os.Stderr, "trowl: no index.html in %s\n", py.CleanPath(dir))
		return 2
	}
	port, _ := strconv.Atoi(a["port"])
	serve(dir, a["host"], port)
	return 0
}

// serve serves a report folder. The folder itself stays plain static files; this only adds
// no-store headers so a rescan shows up on reload instead of a cached copy.
func serve(dir, host string, port int) {
	files := http.FileServer(http.Dir(dir))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// The page is rendered from report.json on each request, with the UI built into this
		// binary, rather than served from the index.html the scan wrote: that file carries the
		// UI as it was at scan time, so a UI change would otherwise need a rescan to show.
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			if raw, err := os.ReadFile(filepath.Join(dir, "report.json")); err == nil {
				if page, ok := report.RenderJSON(raw); ok {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Write(page)
					return
				}
			}
		}
		files.ServeHTTP(w, r)
	})
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trowl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("serving %s at http://%s:%d/ (Ctrl+C to stop)\n", py.CleanPath(dir), host, port)
	http.Serve(ln, handler)
}

func main() {
	argv := os.Args[1:]
	if len(argv) == 0 {
		os.Exit(fail("", "the following arguments are required: cmd"))
	}
	switch argv[0] {
	case "--version":
		fmt.Printf("trowl %s\n", model.Version)
		return
	case "-h", "--help":
		fmt.Println(usage())
		fmt.Println("\nstatic analysis of embedded Linux root filesystems\n\ncommands:")
		for _, c := range commands() {
			fmt.Printf("  %-8s %s\n", c.name, c.help)
		}
		return
	}
	for _, c := range commands() {
		if c.name == argv[0] {
			a, code, ok := parse(c, argv[1:])
			if !ok {
				os.Exit(code)
			}
			os.Exit(c.run(a))
		}
	}
	os.Exit(fail("", fmt.Sprintf("argument cmd: invalid choice: '%s' (choose from 'scan', 'unpack', 'view')", argv[0])))
}
