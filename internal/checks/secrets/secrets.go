// Package secrets finds private keys, baked-in host keys and well-known token formats.
//
// Matched values are never written to the report. Evidence carries their SHA-256
// so identical secrets across images can be correlated.
package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
)

const maxBytes = 4 * 1024 * 1024

var elfMagic = []byte("\x7fELF")

// pemBegin matches the BEGIN line. The matching END line (same kind, within 8192 bytes) is found
// by hand because Go's regexp has no backreferences.
var pemBegin = regexp.MustCompile(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |ED25519 )?PRIVATE KEY)-----`)

const pemMaxBody = 8192

var putty = regexp.MustCompile(`PuTTY-User-Key-File-\d: [\w-]+\r?\nEncryption: ([\w-]+)`)
var puttyEnd = regexp.MustCompile(`(?m)^Private-(?:MAC|Hash): [0-9a-fA-F]+\r?$`)
var privateKeyJSON = regexp.MustCompile(`"private_key"\s*:\s*("-----BEGIN)`)

type token struct {
	check, title string
	re           *regexp.Regexp
}

// Kept to formats with a low false-positive rate.
var tokens = []token{
	{"secrets.aws-access-key", "AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"secrets.github-token", "GitHub token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"secrets.gitlab-token", "GitLab personal access token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"secrets.slack-token", "Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`)},
	{"secrets.google-api-key", "Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
}

// Host keys generated at build time are shared by every device flashed with the image.
var hostKeyPaths = regexp.MustCompile(`^/etc/(?:ssh/ssh_host_\w+_key|dropbear/dropbear_\w+_host_key)$`)

func setHash(value []byte, ev *pyjson.Obj) {
	sum := sha256.Sum256(value)
	ev.Set("sha256", hex.EncodeToString(sum[:]))
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
	var hostKey *pyjson.Obj
	if hostKeyPaths.MatchString(imagePath) {
		hostKey = pyjson.New()
		findings = append(findings, model.Finding{
			Check: "secrets.baked-host-key", Path: imagePath,
			Title: "SSH host key baked into the image",
			Detail: "Every device flashed with this image shares the same host identity; " +
				"generate host keys on first boot instead.",
			Evidence: hostKey,
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
	if hostKey != nil {
		setHash(data, hostKey)
	}
	if bytes.HasPrefix(data, elfMagic) {
		return findings // the ELF checks cover binaries, and keys there are rare and noisy
	}

	for _, m := range pemMatches(data) {
		encrypted := strings.HasPrefix(m.kind, "ENCRYPTED") || bytes.Contains(m.body, []byte("Proc-Type: 4,ENCRYPTED"))
		if m.kind == "OPENSSH PRIVATE KEY" && !encrypted {
			// The base64 body names the cipher, and "none" means an unprotected key.
			// Split on ASCII whitespace only, as Python's bytes.split() does with no argument.
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
		word := "Unencrypted"
		if encrypted {
			word = "Encrypted"
		}
		ev := pyjson.O("offset", m.start, "encrypted", encrypted)
		setHash(data[m.start:m.end], ev)
		findings = append(findings, model.Finding{Check: "secrets.private-key", Path: imagePath,
			Title: fmt.Sprintf("%s %s", word, strings.ToLower(m.kind)), Evidence: ev})
	}
	puttyMatches := putty.FindAllSubmatchIndex(data, -1)
	for i, loc := range puttyMatches {
		encrypted := string(data[loc[2]:loc[3]]) != "none"
		word := "Unencrypted"
		if encrypted {
			word = "Encrypted"
		}
		end := len(data)
		if i+1 < len(puttyMatches) {
			end = puttyMatches[i+1][0]
		}
		// Include the key body, stopping at its MAC instead of unrelated trailing text.
		if tail := puttyEnd.FindIndex(data[loc[1]:end]); tail != nil {
			end = loc[1] + tail[1]
		}
		ev := pyjson.O("offset", loc[0], "encrypted", encrypted)
		setHash(bytes.TrimSpace(data[loc[0]:end]), ev)
		findings = append(findings, model.Finding{Check: "secrets.private-key", Path: imagePath,
			Title: word + " PuTTY private key", Evidence: ev})
	}
	for _, t := range tokens {
		for _, loc := range t.re.FindAllIndex(data, -1) {
			ev := pyjson.O("offset", loc[0])
			setHash(data[loc[0]:loc[1]], ev)
			findings = append(findings, model.Finding{Check: t.check, Path: imagePath,
				Title: t.title, Evidence: ev})
		}
	}
	for _, loc := range privateKeyJSON.FindAllSubmatchIndex(data, -1) {
		// Decode the value so the hash covers the key, not the JSON field marker.
		var key string
		if err := json.NewDecoder(bytes.NewReader(data[loc[2]:])).Decode(&key); err != nil {
			continue
		}
		ev := pyjson.O("offset", loc[0])
		setHash([]byte(key), ev)
		findings = append(findings, model.Finding{Check: "secrets.private-key-json", Path: imagePath,
			Title: "Private key embedded in JSON", Evidence: ev})
	}
	return findings
}
