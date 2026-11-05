package llm

import (
	"reflect"
	"testing"
)

func TestBullets(t *testing.T) {
	reply := "Here is the assessment:\n\n- **Hardening:** 82% of binaries lack a protection.\n* Second point\n• Third point\n4. Fourth point\n5) Fifth point\n- Sixth point\n"
	want := []string{"82% of binaries lack a protection.", "Second point", "Third point", "Fourth point", "Fifth point"}
	if got := bullets(reply); !reflect.DeepEqual(got, want) {
		t.Fatalf("bullets() = %q, want %q", got, want)
	}
	labelled := "- **Systemic hardening weaknesses:** indirect calls are unprotected\n- Vulnerability triage implications: curl needs an update"
	want = []string{"indirect calls are unprotected", "curl needs an update"}
	if got := bullets(labelled); !reflect.DeepEqual(got, want) {
		t.Fatalf("bullets() = %q, want %q", got, want)
	}
	want = []string{"first point", "second point"}
	if got := bullets("Assessment:\n\nfirst point\nsecond point\n"); !reflect.DeepEqual(got, want) {
		t.Fatalf("bullets() = %q, want %q", got, want)
	}
}
