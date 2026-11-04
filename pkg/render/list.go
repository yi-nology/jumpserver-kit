package render

// The list pipeline: the computation every "here are some of them" answer
// goes through.
//
// It lives here because the STEPS and their ORDER are the contract, not a
// detail of any one handler: filter, map, sort, THEN truncate, and count
// the whole matching set. A handler that hand-rolls this order differently
// from its neighbour answers a slightly different question — one caps
// before it sorts (so the caller gets whichever rows the endpoint happened
// to return first, sorted among themselves), and one reports total as the
// unfiltered row count (so "how many matched" reads wrong the moment a
// filter is used). Both drifts were real, in this repository's handlers.
//
// ⚠️ The order is load-bearing:
//
//	filter → map → sort → truncate → count
//
// Sorting BEFORE truncating is what makes "limit=20" mean "the top 20 by
// the sort key" instead of "20 rows, then sorted". Counting AFTER
// filtering is what makes total mean "how many matched". Both are what the
// envelope's three counting fields promise (model/jms.ListMeta).

import (
	"sort"

	"github.com/oekit/pkg/pagination"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// NormLimit clamps a caller's limit argument to what the answer will carry.
//
// It is the ONE place the clamping lives: an unset (or nonsense) limit
// falls back to the tool's default, and a limit past the maximum falls
// back to the default too (the caller asked for more than the endpoint
// will give; the default is the honest answer).
func NormLimit(v, def, max int) int {
	policy := pagination.Policy{
		DefaultPageSize: def,
		MaxPageSize:     max,
		OverMax:         pagination.OverMaxFallback,
	}
	return policy.NormalizeLimit(v)
}

// ListSpec is one list answer's whole computation, spelled out.
//
// S is the source row (usually the bastion's map[string]any), T is the
// contract row (the IDL type). The Map step is where one becomes the other.
type ListSpec[S any, T any] struct {
	// Rows are the source rows, in whatever order the endpoint returned them.
	Rows []S
	// Keep filters the rows; nil keeps them all.
	Keep func(S) bool
	// Map turns a source row into a contract row.
	Map func(S) T
	// Less orders the contract rows; nil keeps source order (stable).
	Less func(a, b T) bool
	// Limit is the caller's raw limit; Def and Max normalise it (NormLimit).
	Limit int
	Def   int
	Max   int
	// Note is the free sentence the answer carries alongside the rows.
	Note string
}

// Build runs the pipeline and returns the standard list envelope.
//
// The three counting fields are computed HERE, not by the caller: count is
// how many rows the answer carries, total is how many matched the filters
// (before the cap), and truncated says the two differ. A handler cannot
// get them subtly wrong because a handler does not compute them any more.
func (s ListSpec[S, T]) Build() ListOf[T] {
	items := make([]T, 0, len(s.Rows))
	for _, row := range s.Rows {
		if s.Keep != nil && !s.Keep(row) {
			continue
		}
		items = append(items, s.Map(row))
	}
	total := len(items)
	if s.Less != nil {
		// Stable, so rows the sort cannot tell apart keep the order the
		// endpoint gave them in.
		sort.SliceStable(items, func(i, j int) bool { return s.Less(items[i], items[j]) })
	}
	// The cap goes LAST, after the sort: limit=20 means "the top 20 by the
	// sort key", not "20 rows, then sorted".
	//
	// A list with NO maximum (Max <= 0) keeps everything that matched: some
	// answers are complete by nature (a short policy table, the node tree,
	// the platform list), and capping those would drop rows the caller needs
	// while reporting truncated for a list that is meant to be whole.
	limit := total
	if s.Max > 0 {
		limit = NormLimit(s.Limit, s.Def, s.Max)
	}
	truncated := total > limit
	if truncated {
		items = items[:limit]
	}
	return ListOf[T]{
		ListMeta: jms.ListMeta{
			Count:     int32(len(items)),
			Total:     int32(total),
			Truncated: truncated,
		},
		Items: items,
		Note:  s.Note,
	}
}
