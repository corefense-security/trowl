package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/pyjson"
)

func TestTokenHashes(t *testing.T) {
	for _, tc := range []struct{ check, value string }{
		{"aws-access-key", "AKIA" + strings.Repeat("A", 16)},
		{"github-token", "ghp_" + strings.Repeat("A", 36)},
		{"github-token", "github_pat_" + strings.Repeat("A", 60)},
		{"gitlab-token", "glpat-" + strings.Repeat("A", 20)},
		{"slack-token", "xoxb-" + strings.Repeat("A", 20)},
		{"google-api-key", "AIza" + strings.Repeat("A", 35)},
	} {
		t.Run(tc.check+tc.value[:4], func(t *testing.T) {
			contents := "before " + tc.value + " after"
			rows := scanText(t, "/etc/app.conf", contents)
			if len(rows) != 1 || rows[0].Check != "secrets."+tc.check {
				t.Fatalf("unexpected findings: %+v", rows)
			}
			requireHash(t, rows[0], []byte(tc.value))
		})
	}
}

func TestPEMHashes(t *testing.T) {
	for _, kind := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "ED25519 PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		t.Run(kind, func(t *testing.T) {
			body := "synthetic-key-data"
			if kind == "OPENSSH PRIVATE KEY" {
				body = base64.StdEncoding.EncodeToString([]byte("openssh-key-v1\x00none"))
			}
			key := "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----"
			contents := "before\n" + key + "\nafter"
			rows := scanText(t, "/etc/key.pem", contents)
			if len(rows) != 1 || rows[0].Check != "secrets.private-key" {
				t.Fatalf("unexpected findings: %+v", rows)
			}
			requireHash(t, rows[0], []byte(key))
			if got := rows[0].Evidence.G("encrypted"); got != (kind == "ENCRYPTED PRIVATE KEY") {
				t.Errorf("encrypted = %v", got)
			}
		})
	}
}

func TestPuTTYHashesIncludeEachKeyBody(t *testing.T) {
	first := "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: first\nPublic-Lines: 1\nAAAA\nPrivate-Lines: 1\nBBBB\nPrivate-MAC: " + strings.Repeat("a", 64)
	second := strings.ReplaceAll(strings.ReplaceAll(first, "first", "second"), "BBBB", "CCCC")
	second = strings.Replace(second, "Encryption: none", "Encryption: aes256-cbc", 1)
	contents := "before\n" + first + "\nunrelated text\n" + second + "\nafter"
	rows := scanText(t, "/etc/key.ppk", contents)
	if len(rows) != 2 {
		t.Fatalf("got %d findings, want two keys", len(rows))
	}
	for i, key := range []string{first, second} {
		requireHash(t, rows[i], []byte(key))
		if rows[i].Evidence.G("encrypted") != (i == 1) {
			t.Errorf("key %d: unexpected encryption status", i)
		}
	}
	if rows[0].Evidence.G("sha256") == rows[1].Evidence.G("sha256") {
		t.Error("different PuTTY keys have the same hash")
	}
}

func TestHostKeyHashes(t *testing.T) {
	for _, path := range []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/dropbear/dropbear_ed25519_host_key"} {
		t.Run(path, func(t *testing.T) {
			value := "\x00synthetic binary host key\xff"
			rows := scanText(t, path, value)
			if len(rows) != 1 || rows[0].Check != "secrets.baked-host-key" {
				t.Fatalf("unexpected findings: %+v", rows)
			}
			requireHash(t, rows[0], []byte(value))
		})
	}
}

func TestJSONHashesCoverDecodedValues(t *testing.T) {
	keys := []string{
		"-----BEGIN PRIVATE KEY-----\nfirst\n-----END PRIVATE KEY-----\n",
		"-----BEGIN PRIVATE KEY-----\nsecond\n-----END PRIVATE KEY-----\n",
	}
	raw, err := json.Marshal([]map[string]string{{"private_key": keys[0]}, {"private_key": keys[1]}})
	if err != nil {
		t.Fatal(err)
	}
	rows := scanText(t, "/etc/credentials.json", string(raw))
	var jsonRows []model.Finding
	for _, row := range rows {
		if row.Evidence.G("preview") != nil {
			t.Error("finding still contains a preview")
		}
		if row.Check == "secrets.private-key-json" {
			jsonRows = append(jsonRows, row)
		}
	}
	if len(jsonRows) != len(keys) {
		t.Fatalf("got %d JSON key findings, want %d", len(jsonRows), len(keys))
	}
	for i, key := range keys {
		requireHash(t, jsonRows[i], []byte(key))
	}
	if jsonRows[0].Evidence.G("sha256") == jsonRows[1].Evidence.G("sha256") {
		t.Error("different JSON keys have the same hash")
	}
}

func TestJSONHashesIgnoreSurroundingContent(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----\nsynthetic \\\"quoted\\\" key\\path\n-----END PRIVATE KEY-----\n"
	value, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"private_key":` + string(value) + `,"project":"first"}`,
		"{\n  \"project\": \"second\",\n  \"private_key\": " + string(value) + "\n}",
	} {
		found := false
		for _, row := range scanText(t, "/etc/credentials.json", raw) {
			if row.Check == "secrets.private-key-json" {
				requireHash(t, row, []byte(key))
				found = true
			}
		}
		if !found {
			t.Fatal("JSON key was not detected")
		}
	}
}

func TestTokenHashIgnoresSurroundingContent(t *testing.T) {
	token := "ghp_" + strings.Repeat("A", 36)
	first := "first config " + token
	second := "second config " + token
	rows := scanText(t, "/etc/first.conf", first)
	other := scanText(t, "/etc/second.conf", second)
	copy := scanText(t, "/etc/copy.conf", first)
	if len(rows) != 1 || len(other) != 1 || len(copy) != 1 {
		t.Fatal("expected one token in each file")
	}
	requireHash(t, rows[0], []byte(token))
	requireHash(t, other[0], []byte(token))
	if rows[0].Evidence.G("sha256") != other[0].Evidence.G("sha256") {
		t.Error("the same token in different files should have the same hash")
	}
	if rows[0].Evidence.G("sha256") != copy[0].Evidence.G("sha256") {
		t.Error("identical contents at different paths should have the same hash")
	}
}

func TestELFContentsSkipped(t *testing.T) {
	contents := string(elfMagic) + "ghp_" + strings.Repeat("A", 36)
	if rows := scanText(t, "/usr/bin/app", contents); len(rows) != 0 {
		t.Fatal("ELF contents should not be scanned for tokens")
	}
}

func TestUnreadHostKeysKeepPathFinding(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "host-key")
		if oversized {
			if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		rows := ScanFile("/etc/ssh/ssh_host_ed25519_key", path)
		if len(rows) != 1 || rows[0].Check != "secrets.baked-host-key" || rows[0].Evidence.G("sha256") != nil {
			t.Fatalf("unread key should retain a path finding without a hash: %+v", rows)
		}
	}
}

func scanText(t *testing.T, imagePath, contents string) []model.Finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return ScanFile(imagePath, path)
}

func requireHash(t *testing.T, finding model.Finding, value []byte) {
	t.Helper()
	sum := sha256.Sum256(value)
	if got := finding.Evidence.G("sha256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("%s hash = %v, want the hash of the matched content", finding.Check, got)
	}
	for _, field := range finding.Evidence.Keys() {
		if field == "preview" {
			t.Error("finding still contains a preview field")
		}
	}
	if bytes.Contains([]byte(pyjson.Default(finding.Obj())), value) {
		t.Error("finding contains the secret value")
	}
}
