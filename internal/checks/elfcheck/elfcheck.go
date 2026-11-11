// Package elfcheck reports compiler and linker hardening properties of every ELF in the image
// (checksec-style).
//
// Each binary gets a property record (used by the report table) and findings for the gaps.
// Kernel modules (ET_REL) are inventoried but not judged here.
package elfcheck

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/pyjson"
)

const (
	dfBindNow = 0x8
	df1Now    = 0x1
	df1PIE    = 0x08000000

	ntGNUPropertyType0   = 5
	propX86Feature1      = 0xc0000002
	propAArch64Feature1  = 0xc0000000
	x86IBT, x86SHSTK     = 0x1, 0x2
	aarch64BTI, aarchPAC = 0x1, 0x2
)

var canarySymbols = map[string]bool{"__stack_chk_fail": true, "__stack_chk_guard": true,
	"__stack_chk_fail_local": true, "__intel_security_cookie": true}

// Functions glibc/musl can redirect to a checked *_chk variant under _FORTIFY_SOURCE.
var fortifiable = map[string]bool{}

func init() {
	for _, s := range strings.Fields(`memcpy memmove memset mempcpy stpcpy stpncpy strcat strcpy
		strncat strncpy sprintf snprintf vsprintf vsnprintf printf fprintf vprintf vfprintf read pread
		pread64 recv recvfrom fgets gets getcwd realpath readlink wcscpy wcsncpy wmemcpy poll ppoll`) {
		fortifiable[s] = true
	}
}

func symbols(f *elf.File) map[string]bool {
	names := map[string]bool{}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_SYMTAB && s.Type != elf.SHT_DYNSYM {
			continue
		}
		var syms []elf.Symbol
		if s.Type == elf.SHT_SYMTAB {
			syms, _ = f.Symbols()
		} else {
			syms, _ = f.DynamicSymbols()
		}
		for _, sym := range syms {
			if sym.Name != "" {
				names[sym.Name] = true
			}
		}
	}
	return names
}

func imports(f *elf.File) map[string]bool {
	out := map[string]bool{}
	if s := f.Section(".dynsym"); s == nil || (s.Type != elf.SHT_DYNSYM && s.Type != elf.SHT_SYMTAB) {
		return out
	}
	syms, _ := f.DynamicSymbols()
	for _, s := range syms {
		if s.Name != "" && s.Section == elf.SHN_UNDEF {
			out[s.Name] = true
		}
	}
	return out
}

type dynamic struct {
	flags, flags1  uint64
	bindNow        bool
	rpath, runpath []string
}

func lastVal(f *elf.File, tag elf.DynTag) (uint64, bool) {
	v, err := f.DynValue(tag)
	if err != nil || len(v) == 0 {
		return 0, false
	}
	return v[len(v)-1], true
}

func lastStr(f *elf.File, tag elf.DynTag) ([]string, bool) {
	v, err := f.DynString(tag)
	if err != nil || len(v) == 0 {
		return nil, false
	}
	return strings.Split(v[len(v)-1], ":"), true
}

func dynamicInfo(f *elf.File) dynamic {
	d := dynamic{rpath: []string{}, runpath: []string{}}
	if f.SectionByType(elf.SHT_DYNAMIC) == nil {
		return d
	}
	d.flags, _ = lastVal(f, elf.DT_FLAGS)
	d.flags1, _ = lastVal(f, elf.DT_FLAGS_1)
	_, d.bindNow = lastVal(f, elf.DT_BIND_NOW)
	if r, ok := lastStr(f, elf.DT_RPATH); ok {
		d.rpath = r
	}
	if r, ok := lastStr(f, elf.DT_RUNPATH); ok {
		d.runpath = r
	}
	return d
}

func align(n, a int) int { return (n + a - 1) &^ (a - 1) }

// cfProtection reads GNU_PROPERTY_*_FEATURE_1_AND from .note.gnu.property.
func cfProtection(f *elf.File) any {
	if f.Machine != elf.EM_X86_64 && f.Machine != elf.EM_386 && f.Machine != elf.EM_AARCH64 {
		return nil
	}
	bo := f.ByteOrder
	propAlign := 8
	if f.Class == elf.ELFCLASS32 {
		propAlign = 4
	}
	var bits uint32
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOTE || s.Name != ".note.gnu.property" {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		noteAlign := int(s.Addralign)
		if noteAlign < 4 {
			noteAlign = 4
		}
		for off := 0; off+12 <= len(data); {
			namesz := int(bo.Uint32(data[off:]))
			descsz := int(bo.Uint32(data[off+4:]))
			ntype := bo.Uint32(data[off+8:])
			nameEnd := off + 12 + align(namesz, 4)
			descEnd := nameEnd + descsz
			if namesz < 0 || descsz < 0 || descEnd > len(data) {
				break
			}
			name := strings.TrimRight(string(data[off+12:off+12+namesz]), "\x00")
			if ntype == ntGNUPropertyType0 && name == "GNU" {
				desc := data[nameEnd:descEnd]
				for p := 0; p+8 <= len(desc); {
					prType := bo.Uint32(desc[p:])
					prSize := int(bo.Uint32(desc[p+4:]))
					if p+8+prSize > len(desc) {
						break
					}
					if (prType == propX86Feature1 || prType == propAArch64Feature1) && prSize >= 4 {
						bits = bo.Uint32(desc[p+8:])
					}
					p += 8 + align(prSize, propAlign)
				}
			}
			off = nameEnd + align(descsz, noteAlign)
		}
	}
	if f.Machine == elf.EM_AARCH64 {
		return pyjson.O("bti", bits&aarch64BTI != 0, "pac", bits&aarchPAC != 0)
	}
	return pyjson.O("ibt", bits&x86IBT != 0, "shstk", bits&x86SHSTK != 0)
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Analyse returns the hardening properties of path, or nil if it isn't a parseable ELF.
func Analyse(path string) (props *pyjson.Obj) {
	defer func() {
		if recover() != nil {
			props = nil
		}
	}()
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	head := make([]byte, 4)
	if n, _ := io.ReadFull(fh, head); n < 4 || !bytes.Equal(head, []byte("\x7fELF")) {
		return nil
	}
	f, err := elf.NewFile(fh)
	if err != nil {
		return nil
	}
	segTypes := map[elf.ProgType]bool{}
	var stack *elf.Prog
	for _, p := range f.Progs {
		segTypes[p.Type] = true
		if p.Type == elf.PT_GNU_STACK && stack == nil {
			stack = p
		}
	}
	hasInterp := segTypes[elf.PT_INTERP]
	dyn := dynamicInfo(f)
	pieFlag := dyn.flags1&df1PIE != 0

	var kind string
	switch {
	case f.Type == elf.ET_REL:
		kind = "object"
		if strings.HasSuffix(filepath.Base(path), ".ko") {
			kind = "module"
		}
	case f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN && (hasInterp || pieFlag):
		kind = "executable"
	case f.Type == elf.ET_DYN:
		kind = "library"
	default:
		kind = "other"
	}

	props = pyjson.O("kind", kind, "arch", machineName(f.Machine),
		"static", kind == "executable" && !segTypes[elf.PT_DYNAMIC])
	if kind != "executable" && kind != "library" {
		return props
	}
	props.Set("nx", stack != nil && stack.Flags&elf.PF_X == 0)
	if kind == "library" {
		props.Set("pie", nil)
	} else {
		props.Set("pie", f.Type == elf.ET_DYN)
	}
	switch {
	case !segTypes[elf.PT_GNU_RELRO]:
		props.Set("relro", "none")
	case dyn.bindNow || dyn.flags&dfBindNow != 0 || dyn.flags1&df1Now != 0:
		props.Set("relro", "full")
	default:
		props.Set("relro", "partial")
	}

	syms := symbols(f)
	// The canary and FORTIFY checks both match symbol names (dynamic imports, or local .symtab
	// entries for a static binary). A stripped static binary has no symbols at all (a stripped
	// dynamic one keeps .dynsym). Then "no canary found" or "0 fortified" would wrongly report
	// a hardening gap.
	noSymbols := len(syms) == 0
	props.Set("no_symbols", noSymbols)
	canary := false
	for s := range syms {
		if canarySymbols[s] {
			canary = true
			break
		}
	}
	props.Set("canary", canary)
	imp := imports(f)
	if len(imp) == 0 {
		imp = syms
	}
	// Each libc function is checked (__f_chk only), mixed (both, because some call sites had no
	// known buffer size) or unchecked (plain f only).
	chk, plain := map[string]bool{}, map[string]bool{}
	for s := range imp {
		if strings.HasPrefix(s, "__") && strings.HasSuffix(s, "_chk") && len(s) >= 6 {
			chk[s[2:len(s)-4]] = true
		} else if strings.HasPrefix(s, "__") && strings.HasSuffix(s, "_chk") {
			chk[""] = true // Python slices "__chk"-like names to ""
		}
		if fortifiable[s] {
			plain[s] = true
		}
	}
	checked, mixed, unchecked := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for s := range chk {
		if plain[s] {
			mixed[s] = true
		} else {
			checked[s] = true
		}
	}
	for s := range plain {
		if !chk[s] {
			unchecked[s] = true
		}
	}
	props.Set("fortify", pyjson.O("fortified", len(chk), "unfortified", len(unchecked),
		"checked", sortedSet(checked), "mixed", sortedSet(mixed), "unchecked", sortedSet(unchecked)))
	props.Set("rpath", dyn.rpath)
	props.Set("runpath", dyn.runpath)
	props.Set("stripped", f.Section(".symtab") == nil)
	props.Set("cf_protection", cfProtection(f))
	return props
}

func machineName(m elf.Machine) any {
	s := m.String()
	if strings.HasPrefix(s, "EM_") {
		return s
	}
	return int(m)
}

func badSearchPath(p string) bool {
	return p == "" || p == "." || !(strings.HasPrefix(p, "/") || strings.HasPrefix(p, "$ORIGIN")) ||
		strings.HasPrefix(p, "/tmp") || strings.HasPrefix(p, "/var/tmp") || strings.HasPrefix(p, "/dev/shm") ||
		strings.HasPrefix(p, "/home")
}

func FindingsFor(imagePath string, props *pyjson.Obj) []model.Finding {
	kind := props.G("kind").(string)
	if kind != "executable" && kind != "library" {
		return nil
	}
	var out []model.Finding
	add := func(check, title, detail string, ev *pyjson.Obj) {
		out = append(out, model.Finding{Check: check, Path: imagePath, Title: title, Detail: detail, Evidence: ev})
	}
	if !props.G("nx").(bool) {
		add("elf.nx", fmt.Sprintf("Executable stack (%s)", kind),
			"PT_GNU_STACK is missing or marked executable; link with -z noexecstack.", nil)
	}
	if pie, ok := props.G("pie").(bool); ok && !pie {
		add("elf.pie", "Executable is not PIE",
			"Loaded at a fixed address, so ASLR does not apply; build with -fPIE -pie.", nil)
	}
	switch props.G("relro") {
	case "none":
		add("elf.relro", fmt.Sprintf("No RELRO (%s)", kind),
			"GOT and other relocation targets stay writable; link with -z relro -z now.", nil)
	case "partial":
		add("elf.relro", fmt.Sprintf("Partial RELRO (%s)", kind),
			"Lazy binding leaves the PLT GOT writable; link with -z now.", nil)
	}
	ff := props.G("fortify").(*pyjson.Obj)
	fortified, unfortified := ff.G("fortified").(int), ff.G("unfortified").(int)
	// Only judge canaries where the binary handles buffers via libc. Stub libraries and the
	// dynamic loader rightly have none.
	if !props.G("canary").(bool) && (unfortified != 0 || fortified != 0) {
		add("elf.canary", fmt.Sprintf("No stack protector symbols (%s)", kind),
			"Calls buffer-handling libc functions but has no __stack_chk_* references; build with -fstack-protector-strong.", nil)
	}
	if unfortified != 0 && fortified == 0 {
		add("elf.fortify", fmt.Sprintf("Not fortified (%s)", kind),
			fmt.Sprintf("Calls %d fortifiable libc function(s) with no *_chk variants; build with -O2 -D_FORTIFY_SOURCE=2 (or 3).", unfortified),
			ff)
	}
	for _, tag := range []string{"rpath", "runpath"} {
		paths := props.G(tag).([]string)
		var bad []string
		for _, p := range paths {
			if badSearchPath(p) {
				bad = append(bad, p)
			}
		}
		if len(bad) > 0 {
			add("elf."+tag, fmt.Sprintf("Insecure %s (%s)", strings.ToUpper(tag), strings.Join(bad, ", ")),
				"A relative or user-writable library search path lets a local user inject libraries.",
				pyjson.O(tag, paths))
		}
	}
	return out
}
