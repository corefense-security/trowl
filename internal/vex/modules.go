package vex

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/corefense-security/trowl/internal/py"
)

// Modules are the in-tree kernel modules an image ships for one kernel
// release, by the object Kbuild builds each from.
//
// modules_install puts the module of object net/sctp/sctp at
// /lib/modules/<release>/kernel/net/sctp/sctp.ko, compressed or not, so the
// path under kernel/ is the object. Out-of-tree modules (extra/, updates/)
// are not objects of the tree and are not read.
type Modules struct {
	Dir     string          // the directory read, as the image names it: /lib/modules/6.18.52-yocto-standard
	objects map[string]bool // net/sctp/sctp, ...
}

// moduleSuffixes are the endings modules_install gives a module, with
// CONFIG_MODULE_COMPRESS_* or without.
var moduleSuffixes = []string{".ko", ".ko.gz", ".ko.xz", ".ko.zst"}

// ReadModules reads the modules the image at rootfs ships for the kernel
// release, such as 6.18.52. It is nil when the image has no module directory
// for that release, or more than one, as then nothing tells which modules
// the kernel loads. A directory with no modules is still read, and the image
// then ships none.
func ReadModules(rootfs, release string) *Modules {
	entries, _ := os.ReadDir(py.InRoot(rootfs, "lib/modules"))
	var dirs []string
	for _, e := range entries {
		// A release directory is named for the kernel's uname -r, which is the
		// version followed by the build's LOCALVERSION, if any.
		n := e.Name()
		if n == release || strings.HasPrefix(n, release+"-") || strings.HasPrefix(n, release+"+") {
			dirs = append(dirs, n)
		}
	}
	if len(dirs) != 1 {
		return nil
	}
	m := &Modules{Dir: "/lib/modules/" + dirs[0], objects: map[string]bool{}}
	kernel := py.InRoot(rootfs, "lib/modules/"+dirs[0]+"/kernel")
	filepath.WalkDir(kernel, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		for _, s := range moduleSuffixes {
			if stem, ok := strings.CutSuffix(d.Name(), s); ok {
				rel, _ := filepath.Rel(kernel, filepath.Join(filepath.Dir(p), stem))
				m.objects[filepath.ToSlash(rel)] = true
				break
			}
		}
		return nil
	})
	return m
}

// Ships reports whether the image has the module of object, such as
// net/sctp/sctp.
func (m *Modules) Ships(object string) bool { return m.objects[object] }

// Path is where the module of object would be, as the image names it.
func (m *Modules) Path(object string) string { return m.Dir + "/kernel/" + object + ".ko" }
