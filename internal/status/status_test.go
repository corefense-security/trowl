package status

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuffer lets a test read the output while a step's timer may be writing it.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func capture(t *testing.T, term bool) *safeBuffer {
	t.Helper()
	buf := &safeBuffer{}
	oldOut, oldTerm, oldColour, oldAfter := out, interactive, colour, announceAfter
	out, interactive, colour = buf, term, false
	t.Cleanup(func() { out, interactive, colour, announceAfter = oldOut, oldTerm, oldColour, oldAfter })
	return buf
}

func TestLogLinesStandAlone(t *testing.T) {
	buf := capture(t, false)
	Start("reading fstab").Ok("3 mounts")
	Start("digging up kernel config").Fail("not found")
	want := "✓ reading fstab: 3 mounts\n✗ digging up kernel config: not found\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLogNamesAStepThatRunsLong(t *testing.T) {
	buf := capture(t, false)
	announceAfter = time.Millisecond
	s := Start("sifting CVEs")
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), "sifting CVEs..\n") {
		if time.Now().After(deadline) {
			t.Fatal("the running step was never named")
		}
		time.Sleep(time.Millisecond)
	}
	s.Ok("")
	if got := buf.String(); !strings.HasSuffix(got, "✓ sifting CVEs\n") {
		t.Fatalf("got %q", got)
	}
}

func TestLogHasNoEscapeCodes(t *testing.T) {
	buf := capture(t, false)
	s := Start("fetching KEV")
	Warn("using stale %s", "kev.json")
	s.Fail("unavailable")
	if got := buf.String(); strings.ContainsAny(got, "\r\x1b") {
		t.Fatalf("got %q", got)
	}
}

func TestWarnKeepsTheLiveLine(t *testing.T) {
	buf := capture(t, true)
	s := Start("fetching KEV")
	Warn("using stale %s", "kev.json")
	s.Ok("")
	want := "  fetching KEV.." + erase + "trowl: using stale kev.json\n  fetching KEV.." + erase + "✓ fetching KEV\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestColourOptIn(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	if useColour(false) || !useColour(true) {
		t.Fatal("colour should follow the terminal")
	}
	t.Setenv("FORCE_COLOR", "1")
	if !useColour(false) {
		t.Fatal("FORCE_COLOR should turn colour on in a log")
	}
	t.Setenv("NO_COLOR", "1")
	if useColour(true) {
		t.Fatal("NO_COLOR should win")
	}
}
