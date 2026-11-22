package kconfig

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corefense-security/trowl/internal/pyjson"
	"gopkg.in/yaml.v3"
)

func TestBaselineFilesLoaded(t *testing.T) {
	want := map[string]int{}
	err := fs.WalkDir(baselineFS, "baseline", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(name, ".yaml") {
			return err
		}
		raw, err := baselineFS.ReadFile(name)
		if err != nil {
			return err
		}
		var entries []Entry
		if err := yaml.Unmarshal(raw, &entries); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		bucket := strings.TrimSuffix(path.Base(name), ".yaml")
		if bucket != "harden" && bucket != "attack_surface" {
			t.Errorf("unexpected bucket %s", name)
		}
		subsystem := strings.TrimPrefix(path.Dir(name), "baseline/")
		for _, e := range entries {
			if e.str("option") == "" || e.str("why") == "" || e.str("ref") == "" || e["expect"] == nil {
				t.Errorf("incomplete entry in %s: %v", name, e)
			}
			if e["arch"] != nil && len(archList(e["arch"])) == 0 {
				t.Errorf("arch must be a nonempty array in %s: %v", name, e)
			}
			want[subsystem+":"+bucket+":"+e.str("option")]++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range LoadBaseline() {
		key := e.str("subsystem") + ":" + e.str("bucket") + ":" + e.str("option")
		want[key]--
	}
	for key, n := range want {
		if n != 0 {
			t.Errorf("baseline loading mismatch for %s: %d entries", key, n)
		}
	}
}

func TestCheckArchitecture(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		want, absent []string
		mmapStatus   string
	}{
		{"x86_64", "CONFIG_X86=y\nCONFIG_X86_64=y\n", []string{"X86_KERNEL_IBT", "X86_MSR", "CFI_CLANG"},
			[]string{"X86_PAE", "ARM64_BTI", "ARM_DEBUG_WX"}, "fail"},
		{"x86_32", "CONFIG_X86=y\nCONFIG_X86_32=y\n", []string{"X86_PAE", "X86_MSR"},
			[]string{"X86_KERNEL_IBT", "ARM64_BTI", "ARM_DEBUG_WX", "CFI_CLANG"}, "fail"},
		{"arm64", "CONFIG_ARM64=y\n", []string{"ARM64_BTI", "CFI_CLANG"},
			[]string{"X86_KERNEL_IBT", "X86_PAE", "X86_MSR", "ARM_DEBUG_WX"}, "fail"},
		{"arm", "CONFIG_ARM=y\n", []string{"ARM_DEBUG_WX", "OABI_COMPAT"},
			[]string{"X86_KERNEL_IBT", "X86_PAE", "X86_MSR", "ARM64_BTI", "CFI_CLANG"}, "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config + "CONFIG_DEFAULT_MMAP_MIN_ADDR=32768\n"
			section := checkConfig(t, config, "")
			rows := entriesByOption(section)
			for _, name := range append(tc.want, "HARDENED_USERCOPY", "DEFAULT_MMAP_MIN_ADDR") {
				if rows[name] == nil {
					t.Errorf("missing check %s", name)
				}
			}
			for _, name := range tc.absent {
				if rows[name] != nil {
					t.Errorf("unrelated architecture check %s", name)
				}
			}
			if row := rows["DEFAULT_MMAP_MIN_ADDR"]; row != nil && row.G("status") != tc.mmapStatus {
				t.Errorf("mapping minimum status = %v, want %s", row.G("status"), tc.mmapStatus)
			}
		})
	}
}

func TestNumericExpectation(t *testing.T) {
	for _, tc := range []struct {
		name, actual string
		expect       int
		want         string
	}{
		{"decimal", "176", 176, "pass"},
		{"hex mask", "0x00b0", 176, "pass"},
		{"wrong mask", "0x00b1", 176, "fail"},
		{"negative", "-1", -1, "pass"},
		{"missing", "", 176, "missing"},
		{"invalid", "n", 176, "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := Config{}
			if tc.actual != "" {
				values["TEST"] = tc.actual
			}
			status, _ := judge(Entry{"option": "TEST", "expect": tc.expect}, values)
			if status != tc.want {
				t.Errorf("status = %s, want %s", status, tc.want)
			}
		})
	}
}

func TestPolicyKeepsBaseline(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	raw := "accept:\n  - option: HARDENED_USERCOPY\n    reason: Device exception\nadd:\n  - option: TEAM_CHECK\n    expect: y\n    arch: [x86]\n"
	if err := os.WriteFile(policy, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rows := entriesByOption(checkConfig(t, "CONFIG_X86=y\nCONFIG_X86_64=y\nCONFIG_TEAM_CHECK=y\n", policy))
	for name, status := range map[string]string{"HARDENED_USERCOPY": "accepted", "TEAM_CHECK": "pass", "X86_KERNEL_IBT": "missing"} {
		if row := rows[name]; row == nil || row.G("status") != status {
			t.Errorf("%s: want %s, got %v", name, status, row)
		}
	}
}

func TestNewChecksRespectSince(t *testing.T) {
	rows := entriesByOption(checkConfig(t, "# Linux/x86_64 6.6.0 Kernel Configuration\nCONFIG_X86=y\nCONFIG_X86_64=y\n", ""))
	for _, name := range []string{"MITIGATION_PAGE_TABLE_ISOLATION", "MITIGATION_SLS", "HARDENED_USERCOPY_DEFAULT_ON"} {
		if row := rows[name]; row == nil || row.G("status") != "na" {
			t.Errorf("%s should be not applicable before introduction: %v", name, row)
		}
	}
}

func checkConfig(t *testing.T, config, policy string) *pyjson.Obj {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "config")
	if err := os.WriteFile(file, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	result, _, err := Check(dir, file, policy)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func entriesByOption(section *pyjson.Obj) map[string]*pyjson.Obj {
	rows := map[string]*pyjson.Obj{}
	for _, item := range section.G("entries").([]any) {
		row := item.(*pyjson.Obj)
		rows[row.G("option").(string)] = row
	}
	return rows
}
