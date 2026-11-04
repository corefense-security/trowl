// Package llm runs the local model (llama.cpp's llama-server). For now: a short plain-English
// summary of the scan.
//
// The model is fetched into the cache directory at scan time (pinned revision, SHA-256
// checked) and runs on CPU. It is only given numbers and titles this scan already computed and
// is told to use nothing else, so it describes the report rather than adding to it. Output is
// cached per model, prompt version and input, so rescanning an unchanged image costs nothing.
package llm

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/corefense/trowl/internal/model"
	"github.com/corefense/trowl/internal/py"
	"github.com/corefense/trowl/internal/pyjson"
)

type spec struct{ Label, File, URL, Sha256 string }

var Models = map[string]spec{
	"qwen3-4b": {"Qwen3 4B", "Qwen3-4B-Q4_K_M.gguf",
		"https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/bc640142c66e1fdd12af0bd68f40445458f3869b/Qwen3-4B-Q4_K_M.gguf",
		"7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"},
	"qwen3-1.7b": {"Qwen3 1.7B", "Qwen3-1.7B-Q8_0.gguf",
		"https://huggingface.co/Qwen/Qwen3-1.7B-GGUF/resolve/90862c4b9d2787eaed51d12237eafdfe7c5f6077/Qwen3-1.7B-Q8_0.gguf",
		"061b54daade076b5d3362dac252678d17da8c68f07560be70818cace6590cb1a"},
}

const (
	DefaultModel  = "qwen3-4b"
	promptVersion = 8
	maxPoints     = 5
)

func ModelNames() []string {
	var out []string
	for k := range Models {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const overviewSystem = "You write one bullet for the key-points panel of a security dashboard about an embedded " +
	"Linux root filesystem image. You get the scan facts for one topic as JSON. Reply with a " +
	"single line of at most 18 words giving the one concrete, meaningful takeaway for that topic: " +
	"lead with the most important number, and add one or two supporting numbers only if they " +
	"change the picture. Terse dashboard style, no topic label, no full stop. Copy numbers " +
	"exactly and keep each number with its own label; never call anything fully hardened, and " +
	"do not call anything secure unless every value says so. Use only these facts: never guess " +
	"causes, invent findings or give advice."

// topicInstructions narrow the bullet for topics where the general rule is not specific enough.
var topicInstructions = map[string]string{
	"Vulnerabilities": "Lead with unpatched CVEs on shipped packages; then CVSS 7.0+ and CISA KEV counts. Example: 5 CVEs unpatched, 2 CVSS 7.0+, 1 KEV in shipped packages",
	"Kernel":          "Lead with total kernel configs failed baseline, how many increase attack-surface, how many decrease hardening (parts of that total, not added to it).",
	"Filesystems":     "Lead with the number of insecure mounts (and whether / (say rootfs) is missing RO flag), secrets found, then unencrypted private keys",
	"Hardening":       "Lead with only executables that are missing PIE, stack protector (canary), or RELRO (any kind- partial or full). Where all three flags are missing, count as one instance",
}

func warn(format string, a ...any) { fmt.Fprintf(os.Stderr, "trowl: "+format+"\n", a...) }

func fileSha256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.CopyBuffer(h, f, make([]byte, 1<<22))
	return hex.EncodeToString(h.Sum(nil))
}

// ensureModel returns the model file, downloading it on first use; "" if it can't be had.
func ensureModel(name, cache string) string {
	sp := Models[name]
	path := filepath.Join(cache, "models", sp.File)
	if py.IsFile(path) {
		return path
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	part := strings.TrimSuffix(path, filepath.Ext(path)) + ".part"
	warn("downloading %s model (one-time, cached in %s)", sp.Label, filepath.Dir(path))
	err := func() error {
		req, _ := http.NewRequest("GET", sp.URL, nil)
		req.Header.Set("User-Agent", "trowl/"+model.Version)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP Error %d", resp.StatusCode)
		}
		f, err := os.Create(part)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.CopyBuffer(f, resp.Body, make([]byte, 1<<22))
		return err
	}()
	if err != nil {
		warn("model download failed: %v", err)
		os.Remove(part)
		return ""
	}
	if fileSha256(part) != sp.Sha256 {
		warn("model download failed its SHA-256 check; discarded")
		os.Remove(part)
		return ""
	}
	os.Rename(part, path)
	return path
}

// Runner holds the llama-server process for one scan; started on the first cache miss.
type Runner struct {
	name, cache string
	cmd         *exec.Cmd
	url         string
	failed      bool
}

func NewRunner(name, cache string) *Runner { return &Runner{name: name, cache: cache} }

func (r *Runner) Close() {
	if r.cmd != nil && r.cmd.Process != nil {
		r.cmd.Process.Kill()
		r.cmd.Wait()
	}
}

func serverBinary() string {
	if p := os.Getenv("TROWL_LLAMA_SERVER"); p != "" {
		return p
	}
	p, _ := exec.LookPath("llama-server")
	return p
}

func (r *Runner) start() bool {
	if r.url != "" {
		return true
	}
	if r.failed {
		return false
	}
	r.failed = true
	bin := serverBinary()
	if bin == "" {
		warn("llama-server (llama.cpp) is not installed; model output skipped")
		return false
	}
	model := ensureModel(r.name, r.cache)
	if model == "" {
		return false
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	r.cmd = exec.Command(bin, "-m", model, "--host", "127.0.0.1", "--port", strconv.Itoa(port),
		"-c", "8192", "-t", strconv.Itoa(runtime.NumCPU()), "--seed", "0", "--jinja", "-np", "1")
	if err := r.cmd.Start(); err != nil {
		warn("llama-server failed to start: %v", err)
		return false
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		resp, err := http.Get(url + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				r.url, r.failed = url, false
				return true
			}
		}
		if r.cmd.ProcessState != nil {
			break
		}
	}
	warn("llama-server did not become ready; model output skipped")
	r.Close()
	return false
}

func (r *Runner) complete(system, user string, maxTokens int) string {
	if !r.start() {
		return ""
	}
	body, _ := json.Marshal(map[string]any{
		// "/no_think" turns off Qwen3's reasoning block.
		"messages": []map[string]string{{"role": "system", "content": system},
			{"role": "user", "content": user + "\n/no_think"}},
		"temperature": 0, "max_tokens": maxTokens, "seed": 0,
	})
	resp, err := http.Post(r.url+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		warn("model request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	var out struct {
		Choices []struct {
			Message struct {
				Content *string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Choices) == 0 || out.Choices[0].Message.Content == nil {
		return ""
	}
	return *out.Choices[0].Message.Content
}

var thinkRe = regexp.MustCompile(`(?s)<think>.*?</think>`)

// chat is one cached completion; ok is false if llama.cpp or the model isn't available.
func (r *Runner) chat(system, user string, maxTokens int) (string, bool) {
	store := filepath.Join(r.cache, "llm-cache.json")
	sum := sha1.Sum([]byte(system + user))
	key := fmt.Sprintf("%s:%d:%s", r.name, promptVersion, hex.EncodeToString(sum[:]))
	known := pyjson.New()
	if raw, err := os.ReadFile(store); err == nil {
		known = decodeStringMap(raw)
	}
	if v, ok := known.Get(key); ok {
		s, _ := v.(string)
		return s, true
	}
	text := strings.TrimSpace(thinkRe.ReplaceAllString(r.complete(system, user, maxTokens), ""))
	if text == "" {
		return "", false
	}
	known.Set(key, text)
	os.MkdirAll(filepath.Dir(store), 0o755)
	os.WriteFile(store, []byte(pyjson.Default(known)), 0o644)
	return text, true
}

// decodeStringMap reads a JSON object of strings keeping its key order.
func decodeStringMap(raw []byte) *pyjson.Obj {
	o := pyjson.New()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return o
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			break
		}
		var v string
		if dec.Decode(&v) != nil {
			break
		}
		o.Set(kt.(string), v)
	}
	return o
}

var topicPrefix = regexp.MustCompile(`^\d+\.\s*`)

// Overview returns key points for the Overview page, as [{topic, text}]: one bullet per facts
// section. Each section is its own request, so a bullet can only use its own section's facts
// and no two bullets can repeat each other.
func Overview(r *Runner, facts *pyjson.Obj) *pyjson.Obj {
	name := r.name
	warn("writing the overview summary with %s", Models[name].Label)
	points := []any{}
	for i, section := range facts.Keys() {
		if i == maxPoints {
			break
		}
		topic := topicPrefix.ReplaceAllString(section, "")
		user := "Topic: " + topic + "\n"
		if ins, ok := topicInstructions[topic]; ok {
			user += ins + "\n"
		}
		text, _ := r.chat(overviewSystem, user+pyjson.Indent1(facts.G(section)), 80)
		line := ""
		if t := py.Strip(text); t != "" {
			line = py.Strip(py.SplitLines(t)[0])
		}
		clean := regexp.MustCompile(`(?i)^[-*\x{2022}\s]*(?:` + regexp.QuoteMeta(topic) + `\s*:\s*)?`)
		line = strings.TrimRight(clean.ReplaceAllString(line, ""), ".")
		if line != "" {
			points = append(points, pyjson.O("topic", topic, "text", strings.ReplaceAll(line, "**", "")))
		}
	}
	if len(points) == 0 {
		return nil
	}
	return pyjson.O("points", points, "model", name, "label", Models[name].Label)
}

// Label is the model's display name.
func (r *Runner) Label() string { return Models[r.name].Label }

// Name is the model's id.
func (r *Runner) Name() string { return r.name }
