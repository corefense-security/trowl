// Package secrets finds private keys, baked-in host keys and well-known token formats.
//
// Matched values are never written to the report in full: evidence carries a short,
// redacted preview and the SHA-256 of the match so identical secrets across images
// can be correlated without leaking them.
package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
)

const maxBytes = 4 * 1024 * 1024

var elfMagic = []byte("\x7fELF")

// The BEGIN line; the matching END line (same kind, within 8192 bytes) is found by hand because
// Go's regexp has no backreferences.
var pemBegin = regexp.MustCompile(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |ED25519 )?PRIVATE KEY)-----`)

const pemMaxBody = 8192

var putty = regexp.MustCompile(`PuTTY-User-Key-File-\d: [\w-]+\r?\nEncryption: ([\w-]+)`)

type token struct {
	check, title, sev string
	re                *regexp.Regexp
}

// Kept to formats with a low false-positive rate.
var tokens = []token{
	{"secrets.aws-access-key", "AWS access key ID", "high", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"secrets.github-token", "GitHub token", "high", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"secrets.gitlab-token", "GitLab personal access token", "high", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"secrets.slack-token", "Slack token", "high", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`)},
	{"secrets.google-api-key", "Google API key", "medium", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"secrets.private-key-json", "Private key embedded in JSON", "high", regexp.MustCompile(`"private_key"\s*:\s*"-----BEGIN`)},
}

// Host keys generated at build time are shared by every device flashed with the image.
var hostKeyPaths = regexp.MustCompile(`^/etc/(?:ssh/ssh_host_\w+_key|dropbear/dropbear_\w+_host_key)$`)

func redact(value []byte, ev *pyjson.Obj) {
	text := py.Latin1(value)
	preview := "…"
	if utf8.RuneCountInString(text) > 6 {
		preview = string([]rune(text)[:6]) + "…"
	}
	sum := sha256.Sum256(value)
	ev.Set("preview", preview).Set("sha256", hex.EncodeToString(sum[:]))
}

type pemMatch struct {
	start, end int
	kind       string
	body       []byte
}

// pemMatches mirrors finditer over -----BEGIN (KIND)-----([\s\S]{0,8192}?)-----END \1-----.
func pemMatches(data []byte) []pemMatch {
	var out []pemMatch
	pos := 0
	for pos <= len(data) {
		loc := pemBegin.FindSubmatchIndex(data[pos:])
		if loc == nil {
			break
		}
		start, bodyStart := pos+loc[0], pos+loc[1]
		kind := string(data[pos+loc[2] : pos+loc[3]])
		end := []byte("-----END " + kind + "-----")
		limit := bodyStart + pemMaxBody + len(end)
		if limit > len(data) {
			limit = len(data)
		}
		if i := bytes.Index(data[bodyStart:limit], end); i >= 0 {
			out = append(out, pemMatch{start, bodyStart + i + len(end), kind, data[bodyStart : bodyStart+i]})
			pos = bodyStart + i + len(end)
			continue
		}
		pos = start + 1
	}
	return out
}

func ScanFile(imagePath, real string) []model.Finding {
	var findings []model.Finding
	if hostKeyPaths.MatchString(imagePath) {
		findings = append(findings, model.Finding{
			Check: "secrets.baked-host-key", Severity: "high", Path: imagePath,
			Title: "SSH host key baked into the image",
			Detail: "Every device flashed with this image shares the same host identity; " +
				"generate host keys on first boot instead.",
		})
	}
	fi, err := os.Stat(real)
	if err != nil || fi.Size() > maxBytes {
		return findings
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return findings
	}
	if bytes.HasPrefix(data, elfMagic) {
		return findings // binaries are covered by the ELF checks; keys there are rare and noisy
	}

	for _, m := range pemMatches(data) {
		encrypted := strings.HasPrefix(m.kind, "ENCRYPTED") || bytes.Contains(m.body, []byte("Proc-Type: 4,ENCRYPTED"))
		if m.kind == "OPENSSH PRIVATE KEY" && !encrypted {
			// The base64 body names the cipher; "none" means an unprotected key.
			// bytes.split() with no argument: ASCII whitespace only
			joined := bytes.Join(bytes.FieldsFunc(m.body, func(r rune) bool {
				return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
			}), nil)
			if len(joined) > 200 {
				joined = joined[:200]
			}
			if raw, ok := py.B64DecodeLenient(append(append([]byte{}, joined...), '=', '=')); ok {
				if len(raw) > 64 {
					raw = raw[:64]
				}
				encrypted = !bytes.Contains(raw, []byte("none"))
			}
		}
		sev, word := "high", "Unencrypted"
		if encrypted {
			sev, word = "medium", "Encrypted"
		}
		ev := pyjson.O("offset", m.start, "encrypted", encrypted)
		redact(data[m.start:m.end], ev)
		findings = append(findings, model.Finding{Check: "secrets.private-key", Severity: sev, Path: imagePath,
			Title: fmt.Sprintf("%s %s", word, strings.ToLower(m.kind)), Evidence: ev})
	}
	for _, loc := range putty.FindAllSubmatchIndex(data, -1) {
		encrypted := string(data[loc[2]:loc[3]]) != "none"
		sev, word := "high", "Unencrypted"
		if encrypted {
			sev, word = "medium", "Encrypted"
		}
		findings = append(findings, model.Finding{Check: "secrets.private-key", Severity: sev, Path: imagePath,
			Title: word + " PuTTY private key", Evidence: pyjson.O("offset", loc[0], "encrypted", encrypted)})
	}
	for _, t := range tokens {
		for _, loc := range t.re.FindAllIndex(data, -1) {
			ev := pyjson.O("offset", loc[0])
			redact(data[loc[0]:loc[1]], ev)
			findings = append(findings, model.Finding{Check: t.check, Severity: t.sev, Path: imagePath,
				Title: t.title, Evidence: ev})
		}
	}
	return findings
}
