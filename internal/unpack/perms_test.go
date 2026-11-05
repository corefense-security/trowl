package unpack

import "testing"

func TestParseExtPerms(t *testing.T) {
	out := "debugfs 1.46.5\n" +
		"debugfs: ls -p \"/\"\n/2/040755/0/0/.//\n/9/100644/0/0/top/5/\n" +
		"debugfs: ls -p \"/bin\"\n/13/040755/0/0/.//\n/38/120777/0/0/gunzip/19/\n/17/104755/0/70/busybox.suid/59520/\n"
	got := parseExtPerms(out)
	if len(got) != 2 || got["/top"] != (Perm{0o644, 0, 0}) || got["/bin/busybox.suid"] != (Perm{0o4755, 0, 70}) {
		t.Errorf("got %v", got)
	}
}

func TestParseSquashPerms(t *testing.T) {
	out := "Parallel unsquashfs: Using 4 processors\n" +
		"drwxr-xr-x 0/0 40 2026-10-27 10:00 squashfs-root\n" +
		"-rwsr-xr-x 0/0 59520 2026-10-27 10:00 squashfs-root/bin/su\n" +
		"-rwxr-sr-x 0/5 10 2026-10-27 10:00 squashfs-root/bin/a b\n" +
		"lrwxrwxrwx 0/0 7 2026-10-27 10:00 squashfs-root/bin/l -> su\n"
	got := parseSquashPerms(out)
	if len(got) != 2 || got["/bin/su"] != (Perm{0o4755, 0, 0}) || got["/bin/a b"] != (Perm{0o2755, 0, 5}) {
		t.Errorf("got %v", got)
	}
}
