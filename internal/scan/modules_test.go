package scan

import "testing"

func TestHasModuleSuffix(t *testing.T) {
	for name, want := range map[string]bool{
		"kvm-intel.ko": true, "nls_cp437.ko.xz": true, "x.ko.gz": true, "x.ko.zst": true,
		"modules.dep": false, "libfoo.so": false, "README.ko.txt": false,
	} {
		if got := hasModuleSuffix(name); got != want {
			t.Errorf("hasModuleSuffix(%q) = %v, want %v", name, got, want)
		}
	}
}
