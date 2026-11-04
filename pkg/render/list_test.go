package render_test

import (
	"reflect"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/render"
)

// The pipeline's ORDER is the contract: sort BEFORE truncate, so limit=2
// means "the top 2 by the sort key" and not "two rows, then sorted". A
// handler that hand-rolled the order the other way answered a different
// question than its neighbour — that drift is what this pins.
func TestListSortsBeforeItTruncates(t *testing.T) {
	got := render.ListSpec[int, int]{
		Rows:  []int{30, 10, 40, 20},
		Map:   func(v int) int { return v },
		Less:  func(a, b int) bool { return a < b },
		Limit: 2,
		Def:   2,
		Max:   100,
	}.Build()
	if !reflect.DeepEqual(got.Items, []int{10, 20}) {
		t.Errorf("items = %v, want [10 20] (the top 2, not the first 2 sorted)", got.Items)
	}
}

// total is how many MATCHED the filters, not how many rows came in and not
// how many survived the cap: "how many matched" reads wrong the moment a
// filter is used otherwise.
func TestListCountsTheWholeMatchingSet(t *testing.T) {
	got := render.ListSpec[int, int]{
		Rows: []int{1, 2, 3, 4, 5},
		Keep: func(v int) bool { return v%2 == 1 },
		Map:  func(v int) int { return v },
		Less: func(a, b int) bool { return a < b },
		// Deliberately over the match count: the cap must not touch the totals.
		Limit: 10,
		Def:   10,
		Max:   100,
	}.Build()
	if got.Total != 3 || got.Count != 3 || got.Truncated {
		t.Errorf("meta = count %d total %d truncated %v, want 3/3/false", got.Count, got.Total, got.Truncated)
	}
	// And when the cap bites: count is the cap, total stays the match count.
	capped := render.ListSpec[int, int]{
		Rows:  []int{1, 2, 3, 4, 5},
		Keep:  func(v int) bool { return v%2 == 1 },
		Map:   func(v int) int { return v },
		Less:  func(a, b int) bool { return a < b },
		Limit: 2,
		Def:   2,
		Max:   100,
	}.Build()
	if capped.Total != 3 || capped.Count != 2 || !capped.Truncated {
		t.Errorf("meta = count %d total %d truncated %v, want 2/3/true", capped.Count, capped.Total, capped.Truncated)
	}
}

// A list with no maximum keeps everything it matched: an answer that is
// complete by nature (the node tree, the platform list) must not report a
// cap it never had, and must not drop rows behind a default page size.
func TestListWithNoMaxKeepsEverything(t *testing.T) {
	got := render.ListSpec[int, int]{
		Rows: []int{5, 3, 9, 1, 7},
		Map:  func(v int) int { return v },
		Less: func(a, b int) bool { return a < b },
		// Max <= 0: no cap. Limit and Def are then ignored.
		Limit: 2,
		Def:   2,
		Max:   0,
	}.Build()
	if got.Count != 5 || got.Total != 5 || got.Truncated {
		t.Errorf("meta = count %d total %d truncated %v, want 5/5/false", got.Count, got.Total, got.Truncated)
	}
	if !reflect.DeepEqual(got.Items, []int{1, 3, 5, 7, 9}) {
		t.Errorf("items = %v, want all five sorted", got.Items)
	}
}

// The caller's limit is clamped to the tool's policy: an unset limit is the
// default, and a limit past the maximum falls back to the default as well
// (the caller asked for more than the answer will give).
func TestNormLimitClampsToThePolicy(t *testing.T) {
	for _, probe := range []struct{ in, want int }{
		{0, 20},
		{-5, 20},
		{50, 50},
		{100, 100},
		{500, 20},
	} {
		if got := render.NormLimit(probe.in, 20, 100); got != probe.want {
			t.Errorf("NormLimit(%d, 20, 100) = %d, want %d", probe.in, got, probe.want)
		}
	}
}
