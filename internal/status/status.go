// Package status prints what a scan is doing, on stderr so stdout stays the result summary.
//
// A finished step is always one self-contained line, so a CI log can be read or grepped as it
// is. On a terminal the running step shows as a live line that the result replaces. Anywhere
// else nothing is rewritten: a step's name is printed only once it has run for announceAfter,
// so a log that stops shows what the scan was doing without doubling every line.
package status

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const (
	tick  = "✓"
	cross = "✗"
	green = "\x1b[32m"
	red   = "\x1b[31m"
	reset = "\x1b[0m"
	erase = "\r\x1b[K" // back to the start of the line and clear it
)

var (
	mu            sync.Mutex // warnings can come from worker goroutines
	out           io.Writer  = os.Stderr
	interactive              = isTerminal()
	colour                   = useColour(interactive)
	live          *Step      // the step on the live line; terminal only
	announceAfter = 2 * time.Second
)

func isTerminal() bool {
	st, err := os.Stderr.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
}

// useColour keeps escape codes out of logs unless asked for: many CI viewers render them, but
// the raw log people download or grep doesn't.
func useColour(terminal bool) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return terminal || os.Getenv("FORCE_COLOR") != ""
}

// Banner lists what the scan will look at, as {name, value} rows under a title.
func Banner(title string, rows ...[2]string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintln(out, title)
	for _, r := range rows {
		fmt.Fprintf(out, "  %-8s %s\n", r[0], r[1])
	}
	fmt.Fprintln(out)
}

// Step is one thing the scan is looking at. End it with Ok or Fail.
type Step struct {
	label   string
	started time.Time
	timer   *time.Timer
}

func (s *Step) pending() string { return "  " + s.label + ".." }

// Start begins a step, named as a short status such as "unpacking filesystem".
func Start(label string) *Step {
	mu.Lock()
	defer mu.Unlock()
	s := &Step{label: label, started: time.Now()}
	if interactive {
		live = s
		fmt.Fprint(out, s.pending())
	} else {
		s.timer = time.AfterFunc(announceAfter, func() {
			mu.Lock()
			defer mu.Unlock()
			if s.timer != nil {
				fmt.Fprintln(out, s.pending())
			}
		})
	}
	return s
}

// Ok ends the step with a green tick: the thing was found and checked.
func (s *Step) Ok(detail string) { s.end(tick, green, detail) }

// Fail ends the step with a red cross: the thing wasn't found, or the step failed.
func (s *Step) Fail(detail string) { s.end(cross, red, detail) }

func (s *Step) end(mark, tint, detail string) {
	mu.Lock()
	defer mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if live == s {
		live = nil
		fmt.Fprint(out, erase)
	}
	if colour {
		mark = tint + mark + reset
	}
	line := mark + " " + s.label
	if detail != "" {
		line += ": " + detail
	}
	if d := time.Since(s.started); d >= time.Second {
		line += fmt.Sprintf(" (%.1fs)", d.Seconds())
	}
	fmt.Fprintln(out, line)
}

// Warn prints a "trowl: " message, leaving any live line intact below it.
func Warn(format string, a ...any) {
	mu.Lock()
	defer mu.Unlock()
	if live != nil {
		fmt.Fprint(out, erase)
	}
	fmt.Fprintf(out, "trowl: "+format+"\n", a...)
	if live != nil {
		fmt.Fprint(out, live.pending())
	}
}
