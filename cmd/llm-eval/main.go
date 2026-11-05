// llm-eval runs the Overview prompt on a facts file, without a scan, and checks the reply against
// the prompt's rules. Edit internal/llm/llm.go or facts.json, then run it again.
//
//	go run ./cmd/llm-eval -model qwen3.5-4b
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corefense-security/trowl/internal/llm"
)

//go:embed facts.json
var sampleFacts string

var (
	bannedRe = regexp.MustCompile(`(?i)\b(immediate|immediately|urgent|massive|mitigate|mitigation|exploitable)\b`)
	labelRe  = regexp.MustCompile(`^[A-Za-z /-]{2,30}:`)
	fixRe    = regexp.MustCompile(`CONFIG_\w+=\w+`)
)

const maxWords = 25

func main() {
	home, _ := os.UserHomeDir()
	model := flag.String("model", llm.DefaultModel, "model to run: "+strings.Join(llm.ModelNames(), ", "))
	cache := flag.String("cache-dir", filepath.Join(home, ".cache", "trowl"), "where models are kept")
	path := flag.String("facts", "", "facts JSON (default: the built-in sample)")
	flag.Parse()

	facts := sampleFacts
	if *path != "" {
		b, err := os.ReadFile(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		facts = string(b)
	}
	if !json.Valid([]byte(facts)) {
		fmt.Fprintln(os.Stderr, "llm-eval: facts are not valid JSON")
		os.Exit(2)
	}

	r := llm.NewRunner(*model, *cache)
	defer r.Close()
	points := llm.Summarise(r, facts)
	if len(points) == 0 {
		fmt.Fprintln(os.Stderr, "llm-eval: no reply; is llama-server on PATH, or TROWL_LLAMA_SERVER set?")
		os.Exit(2)
	}
	for i, p := range points {
		fmt.Printf("%d. %s\n", i+1, p)
	}
	fmt.Println()
	failed := 0
	for _, c := range check(points, facts) {
		mark := "PASS"
		if !c.ok {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("%s  %s\n", mark, c.name)
	}
	if failed > 0 {
		os.Exit(1)
	}
}

type result struct {
	name string
	ok   bool
}

// check holds the rules a program can judge. Whether a bullet is any good is still for a person.
func check(points []string, facts string) []result {
	all := strings.Join(points, "\n")
	out := []result{{fmt.Sprintf("At least 5 bullets (got %d)", len(points)), len(points) >= 5}}
	for i, p := range points {
		n := len(strings.Fields(p))
		out = append(out, result{fmt.Sprintf("bullet %d is under %d words (%d)", i+1, maxWords, n), n < maxWords})
	}
	out = append(out, result{"no banned words: " + strings.Join(bannedRe.FindAllString(all, -1), ", "), !bannedRe.MatchString(all)})
	labelled := false
	for _, p := range points {
		labelled = labelled || labelRe.MatchString(p)
	}
	out = append(out, result{"no bullet starts with a label", !labelled})
	fixes := fixRe.FindAllString(all, -1)
	copied := len(fixes) > 0
	for _, f := range fixes {
		copied = copied && strings.Contains(facts, `"`+f+`"`)
	}
	out = append(out, result{"a kernel Fix is copied exactly: " + strings.Join(fixes, ", "), copied})

	var parsed map[string]map[string]any
	if json.Unmarshal([]byte(facts), &parsed) == nil {
		cve := parsed["1. SBOM and vulnerabilities"]
		if v, ok := cve["Userland package most affected"].(string); ok {
			out = append(out, result{"quotes the most affected package: " + v, strings.Contains(all, v)})
		}
		for _, k := range []string{"Unpatched kernel CVEs", "Unpatched kernel CVEs with a backport for this kernel's stable series"} {
			if v, ok := cve[k].(float64); ok {
				n := fmt.Sprintf("%d", int(v))
				out = append(out, result{fmt.Sprintf("states %s (%s)", k, n), regexp.MustCompile(`\b` + n + `\b`).MatchString(all)})
			}
		}
	}
	return out
}
