// Package vex gives kernel CVEs a VEX status from the kernel they were matched on: is the code a
// CVE record names compiled by this image's config?
//
// The CVE record says which source files a CVE is in, the field sbom-cve-check reads too. kcond
// reads the kernel tree for the config gate of each file, and the gates are evaluated here against
// the config the image's kernel was built with. Nothing comes from the SBOM's list of compiled
// sources, so it works on an SBOM without one, or with no SBOM at all.
package vex

import (
	"context"
	"fmt"
	"path"
	"sort"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/builds"
	"github.com/corefense-security/kcond/dotconfig"
	"github.com/corefense-security/kcond/gate"

	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/corefense-security/trowl/internal/sbom"
)

// VEX statuses and the justifications this package gives, in OpenVEX's words.
const (
	Affected            = "affected"
	NotAffected         = "not_affected"
	UnderInvestigation  = "under_investigation"
	codeNotPresent      = "vulnerable_code_not_present" // the config doesn't compile the code
	componentNotPresent = "component_not_present"       // compiled into a module the image doesn't ship
)

// Evaluator judges a CVE from the files its record names. nil means the files say nothing about
// the build, such as a record that only names documentation.
type Evaluator interface {
	Assess(files []string) *sbom.Assessment
}

// Kernel is an Evaluator for one kernel: a tree, read once, and the config it was built with.
type Kernel struct {
	tree     *gate.Tree
	config   kcond.Config
	build    string
	compiled map[string]string // the files the config's sources include, by the source reaching them
	// modules are the modules the image ships for this kernel, nil when they
	// weren't read: code compiled only into modules then counts as compiled.
	modules *Modules
}

// SetModules gives the modules the image ships, so that a file compiled
// only into modules missing from the image reads as not present.
func (k *Kernel) SetModules(m *Modules) { k.modules = m }

// NewKernel reads the tree at dir for the kernel the config text describes.
func NewKernel(dir string, config []byte) (*Kernel, error) {
	f, err := dotconfig.Read(config)
	if err != nil {
		return nil, fmt.Errorf("the kernel config: %w", err)
	}
	// A defconfig leaves out options that are on by default, and an option left out counts as off.
	if f.Partial {
		return nil, fmt.Errorf("the kernel config looks like a defconfig, which would read default options as off: use the full .config")
	}
	if f.Build == "" {
		return nil, fmt.Errorf("the kernel config doesn't say which architecture it is for")
	}
	tree, err := gate.Open(context.Background(), dir, f.Build)
	if err != nil {
		return nil, fmt.Errorf("--kernel-tree: %w", err)
	}
	compiled, err := tree.Compiled(f.Config)
	if err != nil {
		return nil, fmt.Errorf("--kernel-tree: %w", err)
	}
	return &Kernel{tree: tree, config: f.Config, build: f.Build, compiled: compiled}, nil
}

// Version is the kernel release of the tree, such as 6.18.52.
func (k *Kernel) Version() string { return k.tree.Version }

// Build is the architecture build the config is for, such as x86_64.
func (k *Kernel) Build() string { return k.build }

// Verdicts on one file, as the report gives them.
const (
	compiled    = "compiled"
	notCompiled = "not compiled"
	unknown     = "unknown"
	// notShipped is code the config compiles, but only into modules the
	// image doesn't have: present in the build, absent from the image.
	notShipped = "module not shipped"
)

// judgement is the verdict on one file, with why, for the report.
type judgement struct {
	verdict, reason string
	module          string // the module the verdict rests on, as the image names it; "" for none
	// config is the config values that put the code where reason says, when reason only says
	// where: "CONFIG_IP_SCTP=m && CONFIG_NET=y" beside "sctp.ko not in image".
	config string
}

// evaluate judges one file.
func (k *Kernel) evaluate(f gate.File) judgement {
	switch f.Status {
	case builds.StatusBuilt:
		t, why := k.explain(f.Gate)
		switch t {
		case kcond.True:
			return k.place(f.Links, why)
		case kcond.False:
			return judgement{verdict: notCompiled, reason: why}
		}
		return judgement{verdict: unknown, reason: why}
	case builds.StatusNotBuilt:
		return judgement{verdict: notCompiled, reason: "another architecture's code"}
	case builds.StatusHeader:
		if from, ok := k.compiled[f.Path]; ok {
			return judgement{verdict: compiled, reason: "included by " + from}
		}
		return judgement{verdict: notCompiled, reason: "no compiled source includes it"}
	case builds.StatusMissing:
		return k.missing(f)
	}
	return judgement{verdict: unknown, reason: "no Makefile lists it"}
}

// missing judges a file the record names but this tree lacks: added after
// this release, or moved since. Alone it says nothing, but when no source
// beside it in its directory is compiled, a source there wouldn't be either
// (see gate.File.DirGate). A header gets no such verdict, since any file can
// include it, nor does a file whose directory the tree lacks, as a renamed
// directory may hold the code.
func (k *Kernel) missing(f gate.File) judgement {
	const why = "not in this tree: it may have been added or moved since this release"
	if f.DirGate == "" {
		return judgement{verdict: unknown, reason: why}
	}
	if t, dirWhy := k.explain(f.DirGate); t == kcond.False {
		return judgement{verdict: notCompiled,
			reason: "not in this tree, and no source in " + path.Dir(f.Path) + "/ is compiled: " + dirWhy}
	}
	return judgement{verdict: unknown, reason: why}
}

// explain evaluates one condition from kcond against the config, and says
// why (see explain in explain.go). Unknown covers a condition that can't be
// read or that depends on more than the config.
func (k *Kernel) explain(cond string) (kcond.Tri, string) {
	e, err := kcond.Parse(cond)
	if err != nil {
		return kcond.Unknown, "its gate could not be read"
	}
	t, why, _ := explain(e, k.config)
	if t != e.Eval(k.config) {
		return kcond.Unknown, "internal error: the gate's explanation disagrees with its evaluation"
	}
	if t == kcond.Unknown {
		why = "its gate depends on more than the config: " + why
	}
	return t, why
}

// place says where the code of a file the config compiles goes, from the
// objects its Makefiles compile it into; gateWhy is why it is compiled.
//
// The gate only says that the file is compiled. An m in it doesn't put the
// file in a module: net/ipv6's mcast_snoop.c has the gate CONFIG_IPV6 and is
// built into vmlinux with CONFIG_IPV6=m. Each link says where one way of
// compiling it goes, so:
//
//   - linked into vmlinux any way → compiled: the image has the code;
//   - else a module the image ships → compiled;
//   - else only modules the image lacks → not shipped.
//
// Whenever that can't be told the file stays compiled, as the gate says, so
// that a file is never cleared on a guess: no links (a header, a source
// #included elsewhere), a condition that depends on more than the config, the
// image's modules not read, or a way of compiling it that is neither, such as
// an extra-y object.
func (k *Kernel) place(links []gate.Link, gateWhy string) judgement {
	if len(links) == 0 {
		return judgement{verdict: compiled, reason: gateWhy}
	}
	// Built in any way: the code is in vmlinux, whatever modules hold too.
	//
	// Each judgement says where the code is in reason ("sctp.ko not in image"), the config values
	// that put it there in config, and the module's full path in the image in module, so that the
	// report can show each on a line of its own, to check against the .config and the image.
	unsure := false
	for _, l := range links {
		switch t, why := k.explain(l.Builtin); t {
		case kcond.True:
			return judgement{verdict: compiled, reason: "built into vmlinux", config: why}
		case kcond.Unknown:
			unsure = true
		}
	}
	if unsure {
		return judgement{verdict: compiled, reason: gateWhy + "; whether it is built in depends on more than the config"}
	}
	// Not built in: the modules it is compiled into decide.
	var missing []judgement
	for _, l := range links {
		t, why := k.explain(l.Module)
		ko := path.Base(l.Object) + ".ko"
		switch {
		case t == kcond.Unknown:
			return judgement{verdict: compiled, reason: gateWhy + "; whether it is a module depends on more than the config"}
		case t == kcond.False:
			continue
		case k.modules == nil:
			return judgement{verdict: compiled, reason: ko + ", counted as shipped: the image's modules weren't found", config: why}
		case k.modules.Ships(l.Object):
			return judgement{verdict: compiled, reason: ko + " in image", config: why, module: k.modules.Path(l.Object)}
		}
		missing = append(missing, judgement{reason: ko + " not in image", config: why, module: k.modules.Path(l.Object)})
	}
	if len(missing) == 0 {
		// Compiled, but neither built in nor a module, such as an extra-y
		// object: nothing says the image lacks it.
		return judgement{verdict: compiled, reason: gateWhy}
	}
	// Several only when the file goes into several modules, all missing.
	j := judgement{verdict: notShipped}
	for i, m := range missing {
		if i > 0 {
			j.reason += "; "
			j.module += ", "
			j.config += "; "
		}
		j.reason += m.reason
		j.module += m.module
		j.config += m.config
	}
	return j
}

// Assess follows sbom-cve-check: one compiled file keeps the CVE, and it is cleared only when no
// file it names is. A file that can't be judged leaves it undecided, never cleared. Makefile,
// Kconfig, documentation and tools say nothing either way, so they are left out; a record with
// nothing else gets no verdict.
func (k *Kernel) Assess(files []string) *sbom.Assessment {
	a := &sbom.Assessment{}
	counts := map[string]int{}
	shorts := map[string]string{} // by verdict, the short reason of the first file with it
	for _, f := range k.tree.Files(files) {
		if f.Status == gate.Skipped {
			continue
		}
		j := k.evaluate(f)
		counts[j.verdict]++
		if _, ok := shorts[j.verdict]; !ok {
			shorts[j.verdict] = short(j, f)
		}
		ev := pyjson.O("path", f.Path, "verdict", j.verdict, "gate", f.Gate, "reason", j.reason)
		if j.module != "" {
			ev.Set("module", j.module)
		}
		if j.config != "" {
			ev.Set("config", j.config)
		}
		a.Evidence = append(a.Evidence, ev)
	}
	if len(a.Evidence) == 0 {
		return nil
	}
	a.Status, a.Justification, a.Detail = decide(counts)
	a.Short = shorts[deciding(a)]
	return a
}

// deciding is the file verdict that gave a its status, as decide picks it.
func deciding(a *sbom.Assessment) string {
	switch {
	case a.Status == Affected:
		return compiled
	case a.Status == UnderInvestigation:
		return unknown
	case a.Justification == componentNotPresent:
		return notShipped
	}
	return notCompiled
}

// short is a file's verdict in a few words, for the report's status line: "file not in tree",
// "module not in image". The file's evidence keeps the full reason.
func short(j judgement, f gate.File) string {
	switch j.verdict {
	case compiled:
		switch {
		case j.module != "":
			return "module in image"
		case j.reason == "built into vmlinux":
			return "built in"
		}
		return "code compiled"
	case notShipped:
		return "module not in image"
	case notCompiled:
		return "not compiled"
	}
	switch f.Status {
	case builds.StatusMissing:
		return "file not in tree"
	case builds.StatusBuilt:
		return "gate not decidable"
	}
	return "file not in any Makefile"
}

// decide gives a CVE its status from the verdicts on its files, counted by
// verdict: one file in the image keeps it affected, one undecided file keeps
// it open, and it is cleared only when every file is left out of the image,
// by the config or by a module the image lacks.
func decide(counts map[string]int) (status, justification, detail string) {
	switch {
	case counts[compiled] > 0:
		return Affected, "", "Compiled by this kernel's config"
	case counts[unknown] > 0:
		return UnderInvestigation, "", "Couldn't tell whether this kernel compiles the code"
	case counts[notShipped] > 0:
		// The build has the code, but only in modules missing from the image.
		return NotAffected, componentNotPresent, "Compiled only into kernel modules the image doesn't ship"
	}
	return NotAffected, codeNotPresent, "Source code not compiled by config"
}

// Counts sums what Apply decided, per CVE and component.
type Counts struct {
	NotAffected, Affected, Undecided int
	NoFiles                          int // no file in the CVE record to judge by
	Defies                           int // differs from the SBOM's own verdict
}

// Apply judges the kernel's open CVEs and records the outcome on sb. files gives the files of each
// CVE's record, and inRange the {component, CVE} pairs whose version the CVE record covers.
//
// A fixed CVE stays fixed, as being compiled says nothing about a fix. So does a not_affected the
// SBOM gives for any reason but the config: a disputed CVE doesn't become real by being compiled.
func Apply(sb *sbom.Sbom, ev Evaluator, files map[string][]string, inRange map[[2]string]bool) Counts {
	var n Counts
	scanned := sb.AssessesKernel()
	for _, comp := range sb.KernelComponents() {
		for _, cve := range sb.Vulns.M[comp] {
			stated := sb.Vex(cve, comp)
			if sb.Matched(cve, comp) {
				stated = ""
			}
			if !judged(sb, cve, comp, stated, inRange) {
				continue
			}
			a := assess(ev, files[cve])
			if a == nil {
				n.NoFiles++
				continue
			}
			a.Stated = stated
			if stated != "" {
				// Read before Assess replaces the pair's status, and its note with it.
				a.StatedNotes = sb.VexNotes(cve, comp)
			}
			a.Defies = scanned && defies(stated, a.Status)
			sb.Assess(cve, comp, a)
			switch a.Status {
			case NotAffected:
				n.NotAffected++
			case Affected:
				n.Affected++
			default:
				n.Undecided++
			}
			if a.Defies {
				n.Defies++
			}
		}
	}
	return n
}

func assess(ev Evaluator, files []string) *sbom.Assessment {
	if len(files) == 0 {
		return nil
	}
	sort.Strings(files)
	return ev.Assess(files)
}

// judged reports whether a pair is one the config can decide.
func judged(sb *sbom.Sbom, cve, comp, stated string, inRange map[[2]string]bool) bool {
	switch stated {
	case "fixed":
		return false
	case "not_affected":
		return sb.VexNotes(cve, comp) == sbom.ConfigNote && inRange[[2]string{comp, cve}]
	}
	return true
}

// defies reports whether trowl's status contradicts the SBOM's. Undecided (needs review)
// contradicts a clear, since the SBOM claims to know what trowl can't confirm, but not an
// "affected".
func defies(stated, status string) bool {
	switch stated {
	case Affected:
		return status == NotAffected
	case NotAffected:
		return status != NotAffected
	}
	return false
}
