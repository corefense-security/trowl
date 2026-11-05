package unpack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseExtList(t *testing.T) {
	out := "debugfs: ls -p <2>\n/2/040755/0/0/.//\n/2/040755/0/0/..//\n/9/100644/0/0/top/5/\n/0/000000/0/0//0/\n/13/040755/0/0/bin//\n\n" +
		"debugfs: ls -p <13>\n/13/040755/0/0/.//\n/2/040755/0/0/..//\n/38/120777/0/0/gunzip/19/\n/17/104755/0/70/busybox.suid/59520/\n\n"
	entries, err := parseExtList(out, map[int]string{2: "/", 13: "/bin"})
	if err != nil {
		t.Fatal(err)
	}
	got := extPerms(entries)
	if len(entries) != 4 || len(got) != 2 || got["/top"] != (Perm{0o644, 0, 0}) || got["/bin/busybox.suid"] != (Perm{0o4755, 0, 70}) {
		t.Errorf("got %v", got)
	}
}

func TestParseExtListRefusesUnsafeNames(t *testing.T) {
	head := "debugfs: ls -p <2>\n/2/040755/0/0/.//\n/2/040755/0/0/..//\n"
	for name, entries := range map[string]string{
		"traversal":  "/9/100644/0/0/../../etc/x/5/\n",
		"line break": "/9/100644/0/0/a\nb/5/\n",
		"late dots":  "/9/100644/0/0/../5/\n",
		"duplicate":  "/9/120777/0/0/a/5/\n/10/040755/0/0/a//\n",
		"no name":    "/9/100644/0/0//5/\n",
	} {
		if _, err := parseExtList(head+entries, map[int]string{2: "/"}); err == nil {
			t.Errorf("%s: not refused", name)
		}
	}
}

func TestParseSquashList(t *testing.T) {
	out := "Parallel unsquashfs: Using 4 processors\n" +
		"drwxr-xr-x 0/0 40 2026-10-27 10:00 squashfs-root\n" +
		"-rwsr-xr-x 0/0 59520 2026-10-27 10:00 squashfs-root/bin/su\n" +
		"-rwxr-sr-x 0/5 10 2026-10-27 10:00 squashfs-root/bin/a b\n" +
		"lrwxrwxrwx 0/0 7 2026-10-27 10:00 squashfs-root/bin/l -> su\n"
	got, sizes := parseSquashList(out)
	if len(got) != 2 || got["/bin/su"] != (Perm{0o4755, 0, 0}) || got["/bin/a b"] != (Perm{0o2755, 0, 5}) {
		t.Errorf("got %v", got)
	}
	if len(sizes) != 2 || sizes["/bin/su"] != 59520 {
		t.Errorf("sizes %v", sizes)
	}
}

func TestCheckExtracted(t *testing.T) {
	dest := t.TempDir()
	os.WriteFile(filepath.Join(dest, "a"), []byte("abc"), 0o644)
	if err := checkExtracted(dest, map[string]int64{"/a": 3}); err != nil {
		t.Error(err)
	}
	for name, sizes := range map[string]map[string]int64{
		"missing": {"/a": 3, "/b": 1},
		"cut":     {"/a": 9},
	} {
		if checkExtracted(dest, sizes) == nil {
			t.Errorf("%s: not reported", name)
		}
	}
}
