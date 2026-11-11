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
	oldOut, oldTerm, oldColour, oldAfter, oldAnimate, oldWidth := out, interactive, colour, announceAfter, animate, width
	out, interactive, colour, animate, width = buf, term, false, false, func() int { return 80 }
	t.Cleanup(func() {
		out, interactive, colour, announceAfter, animate, width = oldOut, oldTerm, oldColour, oldAfter, oldAnimate, oldWidth
	})
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
	want := "⠋ fetching KEV" + erase + "trowl: using stale kev.json\n⠋ fetching KEV" + erase + "✓ fetching KEV\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBarInALog(t *testing.T) {
	buf := capture(t, false)
	s := StartBar("advisory links", 8)
	for i := 0; i < 8; i++ {
		s.Tick()
	}
	s.Ok("8 CVEs")
	want := "  advisory links ━━━━━─────────────── 2/8\n" +
		"  advisory links ━━━━━━━━━━────────── 4/8\n" +
		"  advisory links ━━━━━━━━━━━━━━━───── 6/8\n" +
		"✓ advisory links: 8 CVEs\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBarOnATerminal(t *testing.T) {
	buf := capture(t, true)
	s := StartBar("advisory links", 2)
	s.Tick()
	Warn("slow")
	s.Ok("")
	got := buf.String()
	for _, want := range []string{erase + "⠋ advisory links  ━━━━━━━━━━──────────  1/2", erase + "trowl: slow\n", erase + "✓ advisory links\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("no %q in %q", want, got)
		}
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

func TestStageAndBytesOnATerminal(t *testing.T) {
	buf := capture(t, true)
	width = func() int { return 120 }
	s := Start("unpacking filesystem")
	s.Stage("decompressing zstd", 4_000_000)
	s.Add(1_000_000)
	s.drawn = time.Time{} // redraw now, not after redrawGap
	s.Add(1_000_000)
	s.Ok("zstd+ext")
	got := buf.String()
	for _, want := range []string{
		erase + "⠋ unpacking filesystem · decompressing zstd  ━━━━━━━━━━──────────   50%  2.0 MB / 4.0 MB",
		erase + "✓ unpacking filesystem: zstd+ext\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("no %q in %q", want, got)
		}
	}
}

// A log gets no stage lines and no escape codes. The finished line says what was done.
func TestStageInALog(t *testing.T) {
	buf := capture(t, false)
	s := Start("unpacking filesystem")
	s.Stage("extracting ext", 100)
	s.Add(60)
	s.Ok("ext")
	if got := buf.String(); got != "✓ unpacking filesystem: ext\n" {
		t.Fatalf("got %q", got)
	}
}

// The live line is cut to the terminal's width, never the numbers, so it can't wrap.
func TestLiveLineFitsTheTerminal(t *testing.T) {
	capture(t, true)
	width = func() int { return 60 }
	s := &Step{label: "unpacking filesystem", started: time.Now(), stage: "partition 2: extracting squashfs", size: 10, bytes: 5}
	line := s.liveLine()
	if n := visible(line); n > 59 {
		t.Fatalf("%d columns: %q", n, line)
	}
	if !strings.Contains(line, "…") || !strings.HasSuffix(line, "5 B / 10 B") {
		t.Fatalf("got %q", line)
	}
}

func TestBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 999: "999 B", 1500: "1.5 kB", 22_299_138: "22.3 MB", 117_000_000: "117 MB", 3_400_000_000: "3.4 GB"} {
		if got := Bytes(n); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestVisibleSkipsEscapes(t *testing.T) {
	if n := visible(Green + "━━" + Reset + " 1/2"); n != 6 {
		t.Fatalf("visible = %d", n)
	}
}
