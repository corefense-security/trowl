// Package llm runs the local model (llama.cpp's llama-server). For now it writes a short
// plain-English summary of the scan.
//
// The model is fetched into the cache directory at scan time (pinned revision, SHA-256
// checked) and runs on CPU. It is only given numbers and titles this scan already computed and
// is told to use nothing else, so it describes the report rather than adding to it.
package llm

import (
	"bytes"
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

	"github.com/corefense-security/trowl/internal/model"
	"github.com/corefense-security/trowl/internal/py"
	"github.com/corefense-security/trowl/internal/pyjson"
	"github.com/corefense-security/trowl/internal/status"
)

type spec struct{ Label, File, URL, Sha256 string }

var Models = map[string]spec{
	"qwen3-4b": {"Qwen3-4B", "Qwen3-4B-Q4_K_M.gguf",
		"https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/bc640142c66e1fdd12af0bd68f40445458f3869b/Qwen3-4B-Q4_K_M.gguf",
		"7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"},
	"qwen3.5-4b": {"Qwen3.5-4B", "Qwen3.5-4B-Q4_K_M.gguf",
		"https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/resolve/e87f176479d0855a907a41277aca2f8ee7a09523/Qwen3.5-4B-Q4_K_M.gguf",
		"00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4"},
	"qwen3.5-9b": {"Qwen3.5-9B", "Qwen3.5-9B-Q4_K_M.gguf",
		"https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/3885219b6810b007914f3a7950a8d1b469d598a5/Qwen3.5-9B-Q4_K_M.gguf",
		"03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8"},
}

const (
	DefaultModel   = "qwen3.5-4b"
	maxPoints      = 5
	overviewTokens = 600
)

func ModelNames() []string {
	var out []string
	for k := range Models {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const overviewSystem = `You are an embedded Linux security analyst.

/no_think

Review the provided static firmware scan results and produce
a concise security assessment.

Rules:
- Always generate 7 bullet points, each under 30 words.
- Identify the most important security concerns and patterns.
- Explain the finding, its security implication and useful next action.
- Do not simply repeat statistics shown elsewhere.
- Do not invent vulnerabilities, claim reachability or exploitability.
- Avoid generic advice, marketing language, and alarmism.
- Avoid repeating similar observations.
- Use plain, precise technical English.
- Never generate a colon or semi-colon anywhere in the bullet points, unless it comes from a fact handed to you
- Omit categories without meaningful observations.
- Open each bullet with the concrete risk or affected component, so an engineer sees the impact at once.
- Write one bullet each for the kernel config, binaries, secrets, mounts and Userland and Kernel CVEs, and SBOM (if facts are available)
- Use a number only with the flag it belongs to; never merge two flags into one number.
- Describe impact as what an attacker could do if they reach that weakness, not as a certainty.
- Do not use words like "immediate", "urgent", "massive", "exploitable" or that imply them when summarising CVE impacts. Use "critical" only to describe CVE severity.
- Do not deviate from the instructions on how to interpret the facts.

How to read the facts: 
- Binaries: the flag counts overlap. Describe the potential impact of the gaps; do not list the counts.

- Kernel: pick the one most security-impactful option from each list, name it, and state its impact
  tersely, using the Why given with it. Then advise to either disable it (if the Fix says CONFIG_*_*=n), or enable it (if the Fix says CONFIG_*_*=y) 

- Secrets: Directories and files containing "ptest", "test", "tests" or "installed-tests" are probably not real deployments. Carefully
  judge whether such secrets are dev or test fixtures, or real deployment material,
  and raise a concern only for real ones.

- Mounts:
  Describe the most consequential reported insecure mount configuration.
  Name the mount path and missing protection.
  Suggest the potential impact on runtime security.

- Userland Package CVEs:
  Focus on unpatched vulnerabilities in installed packages, highlighting high-severity ones.
  Quote the "Userland package most affected" fact as written, and name any
  CISA KEV entries if applicable. 

- Kernel CVEs: if the facts give them, state the number of unpatched kernel CVEs and how many have a
  backport for this kernel's stable series, both copied exactly, in the CVE bullet.

- SBOM: highlight inconsistencies between the SBOM and installed packages, and their impact on CVE
  analysis. If no SBOM was supplied, write no separate SBOM bullet;

  Return only the bullet points.`

func warn(format string, a ...any) { status.Warn(format, a...) }

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

// ensureModel returns the model file, downloading it on first use. It returns "" if the file
// can't be had.
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

// Runner holds the llama-server process for one scan. The process starts on first use.
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
		// Reasoning is off and sampling is greedy. On these small models reasoning was slower,
		// less accurate and could use up the token limit. The summary should also repeat run to run.
		"messages": []map[string]string{{"role": "system", "content": system},
			{"role": "user", "content": user}},
		"chat_template_kwargs": map[string]any{"enable_thinking": false},
		"temperature":          0, "max_tokens": maxTokens, "seed": 0,
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

// thinkRe matches the reasoning block, including one cut off by the token limit.
var thinkRe = regexp.MustCompile(`(?s)<think>.*?(?:</think>|$)`)

// chat is one completion. It returns "" if llama.cpp or the model isn't available.
func (r *Runner) chat(system, user string, maxTokens int) string {
	return strings.TrimSpace(thinkRe.ReplaceAllString(r.complete(system, user, maxTokens), ""))
}

// labelRe matches the priority headings and section names, which small models copy as prefixes.
var labelRe = regexp.MustCompile(`(?i)^(?:systemic hardening weaknesses|vulnerability triage implications|` +
	`potential credential or private-key exposure|sbom inconsistencies affecting cve analysis|` +
	`kernel|mounts?|secrets?|cves?|sbom|binaries|hardening)\s*:\s*`)

// bulletRe matches a bullet line ("- ", "* ", "• " or "1. ") and captures its text.
var bulletRe = regexp.MustCompile(`^\s*(?:[-*\x{2022}]|\d+[.)])\s+(.+)$`)

// emphasisRe matches markdown bold and code marks, which the page would show literally.
var emphasisRe = regexp.MustCompile("\\*\\*|`")

// Overview returns the key points for the Overview page, as [{topic, text}]. It sends one request
// with every section's facts, so the model can connect findings across them. topic is the
// bullet's position, since a bullet may span sections.
func Overview(r *Runner, facts *pyjson.Obj) *pyjson.Obj {
	name := r.name
	points := []any{}
	for _, line := range Summarise(r, pyjson.Indent1(facts)) {
		points = append(points, pyjson.O("topic", strconv.Itoa(len(points)+1), "text", line))
	}
	if len(points) == 0 {
		return nil
	}
	return pyjson.O("points", points, "model", name, "label", Models[name].Label)
}

// Summarise returns the key points for facts, already as the JSON text the model is sent.
func Summarise(r *Runner, facts string) []string {
	return bullets(r.chat(overviewSystem, "Scan results:\n"+facts, overviewTokens))
}

// bullets returns the reply's bullet lines without their markers, labels or markdown emphasis, at
// most maxPoints of them. Other lines (a heading or preamble) are dropped. If the reply has no
// bullet markers at all, each line that isn't a heading is a point.
func bullets(text string) []string {
	var marked, plain []string
	for _, line := range py.SplitLines(text) {
		s := py.Strip(line)
		if m := bulletRe.FindStringSubmatch(line); m != nil {
			marked = append(marked, m[1])
		} else if s != "" && !strings.HasSuffix(s, ":") {
			plain = append(plain, s)
		}
	}
	lines := marked
	if len(lines) == 0 {
		lines = plain
	}
	var out []string
	for _, line := range lines {
		if s := labelRe.ReplaceAllString(py.Strip(emphasisRe.ReplaceAllString(line, "")), ""); s != "" && len(out) < maxPoints {
			out = append(out, s)
		}
	}
	return out
}
