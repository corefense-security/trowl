// Package status prints what a scan is doing, on stderr so stdout stays the result summary.
//
// A finished step is always one self-contained line, so a CI log can be read or grepped as it
// is. On a terminal the running step shows as a live line that the result replaces. It holds a
// spinner, the step and its current stage, a progress bar when the size of the work is known, and
// the time so far. Anywhere else nothing is rewritten or animated, and colour is off unless asked
// for. There a step's name is printed only once it has run for announceAfter. A log that stops
// then shows what the scan was doing, without every line appearing twice.
package status

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	tick  = "✓"
	cross = "✗"
	erase = "\r\x1b[K" // back to the start of the line and clear it

	barWidth  = 20
	barFilled = "━"
	barEmpty  = "─"
	redrawGap = 100 * time.Millisecond // at most this often for progress, so a fast loop isn't slowed
	spinGap   = 100 * time.Millisecond // the spinner's frame rate
)

// Text styles, as SGR escape codes. Paint and the stderr helpers drop them when colour is off.
const (
	Reset  = "\x1b[0m"
	Bold   = "\x1b[1m"
	Dim    = "\x1b[2m"
	Red    = "\x1b[31m"
	Green  = "\x1b[32m"
	Yellow = "\x1b[33m"
	Blue   = "\x1b[34m"
	Cyan   = "\x1b[36m"
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var (
	mu            sync.Mutex // warnings can come from worker goroutines
	out           io.Writer  = os.Stderr
	interactive              = isTerminal(os.Stderr)
	colour                   = useColour(interactive)
	colourOut                = useColour(isTerminal(os.Stdout)) // for the summary Paint writes to stdout
	animate                  = interactive                      // the spinner's ticker, off in tests
	width                    = termWidth                        // columns of the terminal, for the live line
	live          *Step                                         // the step on the live line, terminal only
	announceAfter = 2 * time.Second
	spinOnce      sync.Once
)

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
}

// useColour keeps escape codes out of logs unless asked for. Many CI viewers render them, but
// the raw log people download or grep doesn't.
func useColour(terminal bool) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return terminal || os.Getenv("FORCE_COLOR") != ""
}

// tint styles text for stderr, or leaves it plain when colour is off.
func tint(style, s string) string {
	if !colour || s == "" {
		return s
	}
	return style + s + Reset
}

// Paint styles text for stdout, or leaves it plain when stdout isn't a terminal (or NO_COLOR).
func Paint(style, s string) string {
	if !colourOut || s == "" {
		return s
	}
	return style + s + Reset
}

// Banner lists what the scan will look at, as {name, value} rows under a title.
func Banner(title string, rows ...[2]string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintln(out, tint(Bold, title))
	for _, r := range rows {
		fmt.Fprintf(out, "  %s %s\n", tint(Dim, fmt.Sprintf("%-8s", r[0])), r[1])
	}
	fmt.Fprintln(out)
}

// Step is one thing the scan is looking at. End it with Ok or Fail.
type Step struct {
	label   string
	started time.Time
	timer   *time.Timer

	// A step counted in units (StartBar and Tick).
	total, done int
	quarter     int // the last quarter printed to a log

	// The current stage of a step that has several (Stage), and its progress in bytes when
	// the size is known (Add).
	stage       string
	bytes, size int64

	drawn time.Time // when the live line was last redrawn
	frame int       // the spinner frame
}

// logLine is how a running step reads in a log, with no spinner, colour or anything that changes.
func (s *Step) logLine() string {
	if s.total == 0 {
		return "  " + s.label + ".."
	}
	return fmt.Sprintf("  %s %s %d/%d", s.label, bar(s.done, s.total, false), s.done, s.total)
}

// liveLine is the running step on a terminal, fitted to its width.
func (s *Step) liveLine() string {
	head := s.label
	if s.stage != "" {
		head += " · " + s.stage
	}
	var tail []string // after the label, each already styled
	switch {
	case s.total > 0:
		tail = append(tail, bar(s.done, s.total, true), fmt.Sprintf("%d/%d", s.done, s.total))
	case s.size > 0:
		done := min(s.bytes, s.size)
		tail = append(tail, bar(int(1000*done/s.size), 1000, true),
			fmt.Sprintf("%3d%%", 100*done/s.size), tint(Dim, Bytes(done)+" / "+Bytes(s.size)))
	}
	if d := time.Since(s.started); d >= time.Second {
		tail = append(tail, tint(Dim, fmt.Sprintf("%.0fs", d.Seconds())))
	}
	rest := ""
	if len(tail) > 0 {
		rest = "  " + strings.Join(tail, "  ")
	}
	// Shorten the label and stage, never the numbers, so the line fits and is never wrapped (a
	// wrapped live line can't be erased).
	spin := tint(Cyan, spinner[s.frame%len(spinner)]) + " "
	if room := width() - 1 - visible(spin) - visible(rest); utf8.RuneCountInString(head) > room {
		head = cut(head, room)
	}
	return spin + head + rest
}

// bar draws done of total as a fixed-width bar, with the filled part green on a terminal.
func bar(done, total int, styled bool) string {
	filled := barWidth * done / total
	f, e := strings.Repeat(barFilled, filled), strings.Repeat(barEmpty, barWidth-filled)
	if styled {
		return tint(Green, f) + tint(Dim, e)
	}
	if colour {
		f = Green + f + Reset
	}
	return f + e
}

// Bytes formats a size for people, such as 512 B, 3.4 MB or 1.2 GB (powers of 1000, as disk sizes are).
func Bytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n), -1
	for v >= unit && i < 3 {
		v /= unit
		i++
	}
	if v >= 100 {
		return fmt.Sprintf("%.0f %cB", v, "kMGT"[i])
	}
	return fmt.Sprintf("%.1f %cB", v, "kMGT"[i])
}

// visible counts the columns a string takes, leaving out escape codes.
func visible(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			esc = r != 'm'
		case r == '\x1b':
			esc = true
		default:
			n++
		}
	}
	return n
}

// cut shortens plain text to n columns, marking the cut with an ellipsis.
func cut(s string, n int) string {
	if n <= 1 {
		return ""
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// redraw replaces the live line with s's current state. The caller holds mu.
func (s *Step) redraw() {
	s.drawn = time.Now()
	fmt.Fprint(out, erase+s.liveLine())
}

// spin advances the spinner of whatever step is live, so a step that runs long without
// progress still shows it's alive. One ticker for the whole run, started with the first step.
func spin() {
	for range time.Tick(spinGap) {
		mu.Lock()
		if live != nil {
			live.frame++
			live.redraw()
		}
		mu.Unlock()
	}
}

// show makes s the live line on a terminal, or arranges for it to be named in a log if it
// runs long. The caller holds mu.
func (s *Step) show() {
	if interactive {
		live = s
		fmt.Fprint(out, s.liveLine())
		if animate {
			spinOnce.Do(func() { go spin() })
		}
		return
	}
	s.timer = time.AfterFunc(announceAfter, func() {
		mu.Lock()
		defer mu.Unlock()
		if s.timer != nil {
			fmt.Fprintln(out, s.logLine())
		}
	})
}

// Start begins a step, named as a short status such as "unpacking filesystem".
func Start(label string) *Step {
	mu.Lock()
	defer mu.Unlock()
	s := &Step{label: label, started: time.Now()}
	s.show()
	return s
}

// StartBar begins a step of total units of work, shown as a progress bar. Call Tick after each
// unit. A log gets a line at each quarter, so a long step shows it's moving without flooding it.
func StartBar(label string, total int) *Step {
	mu.Lock()
	defer mu.Unlock()
	s := &Step{label: label, started: time.Now(), total: total}
	if interactive {
		live = s
		fmt.Fprint(out, s.liveLine())
		if animate {
			spinOnce.Do(func() { go spin() })
		}
	}
	return s
}

// Tick records one finished unit of a bar step. Workers may call it at the same time.
func (s *Step) Tick() {
	mu.Lock()
	defer mu.Unlock()
	s.done++
	if live == s {
		if time.Since(s.drawn) >= redrawGap {
			s.redraw()
		}
	} else if q := 4 * s.done / s.total; !interactive && q > s.quarter && q < 4 {
		s.quarter = q
		fmt.Fprintln(out, s.logLine())
	}
}

// Stage names what a step is doing now, such as "decompressing zstd", with the bytes it will
// take (0 when unknown) for Add to count against. Only a terminal shows it. The finished line
// says what was done, and a log line per stage would only add noise.
func (s *Step) Stage(name string, size int64) {
	mu.Lock()
	defer mu.Unlock()
	s.stage, s.bytes, s.size = name, 0, size
	if live == s {
		s.redraw()
	}
}

// Add counts n more bytes of the current stage. Readers and pollers may call it often, but the
// line is redrawn at most every redrawGap.
func (s *Step) Add(n int64) {
	mu.Lock()
	defer mu.Unlock()
	s.bytes += n
	if live == s && time.Since(s.drawn) >= redrawGap {
		s.redraw()
	}
}

// Ok ends the step with a green tick, meaning the thing was found and checked.
func (s *Step) Ok(detail string) { s.end(tick, Green, detail) }

// Fail ends the step with a red cross, meaning the thing wasn't found or the step failed.
func (s *Step) Fail(detail string) { s.end(cross, Red, detail) }

func (s *Step) end(mark, style, detail string) {
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
	line := tint(style, mark) + " " + s.label
	if detail != "" {
		line += ": " + detail
	}
	if d := time.Since(s.started); d >= time.Second {
		line += tint(Dim, fmt.Sprintf(" (%.1fs)", d.Seconds()))
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
	fmt.Fprintf(out, tint(Yellow, "trowl:")+" "+format+"\n", a...)
	if live != nil {
		fmt.Fprint(out, live.liveLine())
	}
}
