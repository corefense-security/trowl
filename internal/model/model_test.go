package model

import "testing"

func TestFromBuildInfo(t *testing.T) {
	const rev = "32a47fadaf2e0123456789abcdef0123456789ab"
	for _, c := range []struct {
		name, v, rev string
		dirty        bool
		want         string
	}{
		{"go install of a tag", "v1.2.3", "", false, "1.2.3"},
		{"go install of a commit", "v0.0.0-20261105025515-32a47fadaf2e", "", false, "0.0.0-20261105025515-32a47fadaf2e"},
		{"local build on a tag", "v1.2.3", rev, false, "1.2.3"},
		{"local build past a tag", "v1.2.4-0.20261105025515-32a47fadaf2e", rev, false, "0.1.0-dev+32a47fa"},
		{"untagged local build", "v0.0.0-20261105025515-32a47fadaf2e", rev, false, "0.1.0-dev+32a47fa"},
		{"uncommitted local build", "v0.0.0-20261105025515-32a47fadaf2e+dirty", rev, true, "0.1.0-dev+32a47fa.dirty"},
		{"older Go", "(devel)", rev, false, "0.1.0-dev+32a47fa"},
		{"no version at all", "", "", false, "0.1.0-dev"},
	} {
		if got := fromBuildInfo(c.v, c.rev, c.dirty); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
