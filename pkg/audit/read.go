package audit

// read.go reads the trail back.
//
// The trail is written by the two servers and read by whoever has to answer
// "what happened" — an operator with a terminal, and an agent with the query
// tool. Both read the same files, so both read them through here.
//
// The rules of reading a file that is being written while it is read:
//
//   - a line that cannot be parsed is SKIPPED, not fatal. The file is
//     appended to while it is read, so a half-written last line is a normal
//     thing to find, and it is not a reason to refuse the whole answer;
//   - a file that cannot be read is skipped, not fatal. Another process may
//     be rotating it, or it may belong to a user this process cannot open;
//   - a line that is not ONE OF OURS is skipped, not fatal. The trail
//     directory holds whatever the operator put next to it, and a foreign
//     file is not a fact about what was attempted here;
//   - the newest line comes first. A question about "what just happened"
//     wants the recent lines, not the oldest ones.
//
// The files are read newest first and the reading stops once enough lines
// have been found — but the COUNT of what matched is still complete, because
// a caller that reports "50 of 300" has to know the 300.

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yi-nology/jumpserver-kit/pkg/fspath"
)

// ReadOptions filters what Read returns.
type ReadOptions struct {
	// Dir is where the trail files are.
	Dir string
	// Service keeps only the lines of this server.
	Service string
	// Tool keeps only the lines of this tool.
	Tool string
	// Client keeps only the lines of this MCP client — the "who".
	Client string
	// Allowed keeps only the lines with this verdict — "not stopped" versus
	// "stopped". A nil value keeps both: a refusal and an allowance are
	// equally worth seeing.
	//
	// ⚠️ A call that BROKE is "not stopped" (it went through and failed),
	// so it is on the allowed side. The failures are the `failed` filter's
	// business.
	Allowed *bool
	// Refused keeps only the lines a tool refused. A nil value keeps both.
	//
	// It is the filter that answers "who was stopped": a rehearsal is not
	// a refusal, and it has to be possible to ask for the refusals alone.
	Refused *bool
	// Delivery keeps only the lines with this delivery state — "not_sent"
	// (it never left this process) or "maybe_sent" (it may already be
	// running on the machine). An empty value keeps both.
	//
	// It is the filter that answers "what may still be running out
	// there?", which is the question a caller cannot work out for itself
	// after a failure.
	Delivery string
	// Failed keeps only the lines of the calls whose WORK failed — the tool
	// answered with an error. A nil value keeps both.
	//
	// It is the filter that answers "what went wrong here": a tool that
	// answers with an error result still made a successful protocol call,
	// so the failure is a column of the trail, not a verdict. A call the
	// GATE stopped is not in here — the gate stopping something is the
	// gate working, not a broken call.
	Failed *bool
	// Since keeps only the lines at or after this moment.
	Since time.Time
	// Limit is how many lines to return at most. Zero means 50, and it
	// never goes above MaxReadLimit.
	Limit int
}

// DefaultReadLimit is how many lines a read returns when nothing else is
// asked for.
const DefaultReadLimit = 50

// MaxReadLimit is the most lines one read will ever return.
//
// ⚠️ The limit has to have a ceiling. The trail's answer is a LIST, and a
// list with no ceiling is a list that can fill the caller's context (or the
// server's memory) in one call: "how many lines to return at most" promised
// a bound that did not exist. The count of everything that matched is still
// reported, so the caller can narrow the question down and ask again.
const MaxReadLimit = 500

// trailGlob is the pattern that finds the CANDIDATE trail files.
//
// ⚠️ It has to match the ROTATED file too. Rotation moves the current file
// aside to "<name>.jsonl.1" and starts a fresh "<name>.jsonl" (see file.go),
// and a pattern that only matched "*.jsonl" therefore stopped seeing HALF
// the trail the moment the file rotated — while still answering "nothing
// matched". That is the worst kind of answer an audit can give: a
// true-looking silence over exactly the lines that are hardest to get back
// any other way.
//
// The pattern is deliberately LOOSE: the candidates it finds are checked
// against trailFileName before anything is read out of them, because a
// directory that holds the trail also holds whatever the operator put next
// to it (a ".bak", a compressed copy, their own notes).
const trailGlob = "audit-*.jsonl*"

// trailFileName is the shape of the names THIS package writes.
//
// It is the check that keeps a neighbouring file out of the answer: the
// candidate pattern is loose, so the name decides. A copy called
// "audit-….jsonl.bak" is not a trail file, and reading it would put a
// duplicate of the trail (or something else entirely) into the answer — and
// the duplicate would be counted in "everything that matched", which is a
// number an operator takes as a fact.
//
// The shape is pinned by a test that uses the WRITER to produce the name,
// so the two cannot drift apart: a reader that stops recognising the files
// the writer produces is a trail that has quietly gone blind.
var trailFileName = regexp.MustCompile(`^audit-\d{8}-\d+-[0-9a-f]{8}\.jsonl(\.\d+)?$`)

// Read returns the trail's lines, newest first, and how many lines matched.
//
// The count is of everything that matched, not of what was returned: a
// caller that says "50 of 300" is telling the truth about both numbers, and
// the difference is the whole point of having both.
//
// ⚠️ The memory it holds does NOT grow with the size of the trail: the
// files are read one line at a time, and only the newest `limit` lines are
// kept. There is one file per PROCESS (a server restart starts a new one),
// so the number of files grows with the number of restarts, and a read that
// kept a full file's worth of lines per file would hold the whole trail in
// memory to answer a question that wants a handful of lines.
// Result is what a read found.
type Result struct {
	// Entries are the lines, newest first.
	Entries []Entry
	// Total is how many lines matched — everything that matched, not
	// just what was returned.
	Total int
	// Skipped is how many lines the reader could not take.
	//
	// Two kinds of line cannot be taken: a line LONGER than the reader's
	// line limit, and a line that does not parse. Both are counted, and
	// both are reported — a reader that dropped lines has NOT seen the
	// whole trail, and an answer that says "that is everything" while
	// quietly dropping lines is the same true-looking silence this
	// package exists to end.
	//
	// ⚠️ It counts the lines that could be ABOUT WHAT WAS ASKED FOR. A
	// broken line cannot be filtered, so the count is of the lines that
	// cannot be proved irrelevant (see unreadableIsRelevant) — counting
	// the ones that have nothing to do with the question would make the
	// count noise, and an agent would read it as "a refusal I asked for
	// is missing".
	//
	// ⚠️ The one kind that is NOT counted is a half-written LAST line:
	// it is a line being written RIGHT NOW, so it is not broken, it is
	// not finished — and the next read will see it whole. Counting it
	// would be a false alarm on every read of a live trail.
	Skipped int
}

// EffectiveLimit is the limit a Read will actually use for this ask: the
// default when none was given, capped at the ceiling the trail allows.
//
// It exists so an answer can SAY the limit in force without re-deriving it:
// a note that quotes a different number than the reader used is a true
// sentence about the wrong thing. ⚠️ It clamps to MaxReadLimit — it is NOT
// render.NormLimit, which falls back to a default above its ceiling; the
// two answer different questions.
func EffectiveLimit(asked int) int {
	switch {
	case asked <= 0:
		return DefaultReadLimit
	case asked > MaxReadLimit:
		return MaxReadLimit
	default:
		return asked
	}
}

func Read(opts ReadOptions) (Result, error) {
	limit := EffectiveLimit(opts.Limit)
	// ⚠️ An empty directory means there is NO trail file — and the writer
	// says so too: openTrail returns nil for an empty Dir, which is what
	// "the file trail is off" means.
	//
	// The two sides must say the SAME thing about the same empty value.
	// They did not: filepath.Join("", "audit-*.jsonl*") is a RELATIVE
	// pattern, so the reader went looking in the process's current
	// directory — while the writer had written nothing at all. The
	// consequence is not a wrong count: any file in the working directory
	// that happens to have a trail file's NAME is read back as a fact
	// about what was attempted on this machine. A name is a shape, not a
	// provenance.
	dir := strings.TrimSpace(fspath.ExpandHome(opts.Dir))
	if dir == "" {
		return Result{}, nil
	}
	paths, err := filepath.Glob(filepath.Join(dir, trailGlob))
	if err != nil {
		return Result{}, err
	}
	// The newest file first: the lines an operator is after are in the file
	// that was written last.
	sort.SliceStable(paths, func(i, j int) bool {
		return modTime(paths[i]).After(modTime(paths[j]))
	})

	kept := &newest{limit: limit}
	res := Result{}
	for _, path := range paths {
		// The name decides whether this is a trail file at all.
		if !trailFileName.MatchString(filepath.Base(path)) {
			continue
		}
		matched, skipped, err := readEntries(path, opts, kept)
		// ⚠️ The counts are taken even when the read failed: the lines
		// that WERE read are already in the answer, and dropping the
		// count would make "everything that matched" smaller than the
		// answer itself — and "truncated" would say "no" while the
		// answer is obviously cut.
		res.Total += matched
		res.Skipped += skipped
		if err != nil {
			// A file that cannot be read is skipped, not fatal: another
			// process may be rotating it, or it may belong to a user this
			// process cannot open.
			continue
		}
	}
	res.Entries = kept.sorted()
	return res, nil
}

// newest keeps the newest lines it is handed.
//
// It is bounded: whatever is older than the limit is dropped as it arrives,
// so the memory a read holds does not grow with the size of the trail.
//
// ⚠️ It carries the PARSED moment alongside each line. The ordering is
// then a comparison of times, not of strings — and the two are not the
// same: RFC3339Nano drops the trailing zeros of the fraction, so the exact
// second ("…:00Z") sorts AFTER the half second ("…:00.5Z") as text while
// being the EARLIER of the two. Comparing the strings put the older line
// first in a list that is supposed to be newest-first, and the newest line
// is the one an operator is looking for.
//
// Carrying the moment also means there is no "what if it cannot be read"
// branch to get wrong: a line that cannot be placed in time never reaches
// this point (see isTrailFact).
type newest struct {
	limit int
	items []moment
}

// moment is one line and when it happened.
type moment struct {
	entry Entry
	at    time.Time
}

// add puts one line in, dropping the oldest one when there are too many.
//
// ⚠️ The one that is dropped is the oldest **BY TIME**, not the one that
// arrived first. The files are read newest-file-first, but that is the
// order of their modification times, not of their lines: a long-running
// process's file can still be receiving lines while a newer process's
// file sits idle. So arrival order is not time order, and a queue that
// dropped by arrival would end up keeping the OLDEST lines — the opposite
// of what the trail promises.
func (n *newest) add(e Entry, at time.Time) {
	n.items = append(n.items, moment{entry: e, at: at})
	if len(n.items) >= 2*n.limit {
		// Keep the newest `limit` so far. The sort is O(limit log limit)
		// and happens once every `limit` lines.
		sort.SliceStable(n.items, func(i, j int) bool {
			return n.items[i].at.After(n.items[j].at)
		})
		n.items = n.items[:n.limit]
	}
}

// sorted returns the lines, newest first — and never more than the limit.
func (n *newest) sorted() []Entry {
	sort.SliceStable(n.items, func(i, j int) bool {
		return n.items[i].at.After(n.items[j].at)
	})
	if len(n.items) > n.limit {
		// The newest are at the front after the sort.
		n.items = n.items[:n.limit]
	}
	out := make([]Entry, 0, len(n.items))
	for _, m := range n.items {
		out = append(out, m.entry)
	}
	return out
}

// maxTrailLine is the longest trail line a read accepts.
//
// A line is a call's arguments (cut to 500 bytes) plus a handful of
// columns, so it is a couple of kilobytes at most. The limit is here so
// that a file with a runaway line cannot make the reader hold it in memory;
// a line longer than this is skipped with a note, not silently.
var maxTrailLine = 1 << 20

// readEntries reads one trail file: it counts what matched, counts the
// lines it had to skip, and hands the matching lines to `kept`.
//
// The file is read LINE BY LINE, not whole: the trail's files can be tens
// of megabytes each, and reading them whole would put the whole trail in
// memory for the sake of a query that answers with a handful of lines.
//
// ⚠️ It is read with a bufio.Reader and NOT a bufio.Scanner. The scanner
// STOPS at a line longer than its buffer (`ErrTooLong`) — and that would
// abandon the REST of the file: one huge line would make everything after
// it unreadable, silently. A reader that hits a long line skips THAT line
// and carries on, and says how many it skipped.
// openTrailFile opens a trail file for reading.
//
// ⚠️ It is a variable so that a test can hand the reader a stream that
// FAILS IN THE MIDDLE. That is the one path where the counts have to be
// right — the lines that WERE read are already in the answer, so dropping
// their count would make "everything that matched" smaller than the answer
// itself, and "truncated" would say "no" while the answer is obviously cut.
// Without a seam there is no way to reach that path, and a path that
// cannot be reached cannot be guarded.
//
// ⚠️ It is a package-level variable, so it is shared state on the read
// path. Nothing in this package runs its tests in parallel today (and
// `go test -race` is clean), but a parallel test that replaced it while
// another read was running would race. The seam is worth keeping; a
// reader struct would be the tidier home for it.
var openTrailFile = func(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

func readEntries(path string, opts ReadOptions, kept *newest) (matched, skipped int, err error) {
	f, err := openTrailFile(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	return readStream(f, opts, kept, modTime(path))
}

// readStream reads the trail out of a stream.
//
// ⚠️ It is a function of its own so that a test can drive the reader with a
// stream that FAILS IN THE MIDDLE. That is the one path where the counts
// have to be right — the lines that WERE read are already in the answer, so
// dropping their count would make "everything that matched" smaller than
// the answer itself — and it was the one path nothing could reach before,
// because it needs a file that breaks halfway through.
//
// ⚠️ It reads with a bufio.Reader and NOT a bufio.Scanner. The scanner
// STOPS at a line longer than its buffer (`ErrTooLong`) — and that would
// abandon the REST of the file: one huge line would make everything after
// it unreadable, silently. A reader that hits a long line skips THAT line
// and carries on, and says how many it skipped.
// halfWrittenGrace is how long a half-written LAST line is still treated
// as "being written right now" rather than as a broken line.
//
// ⚠️ The exemption has to end. A process killed mid-write (SIGKILL, OOM,
// a power cut) leaves a half line at the end of its file, and that file
// is one file per PROCESS — so the half line is the last line FOREVER.
// The write side's newline only appears when Write RETURNS an error, and
// a killed process never gets there. Without a time limit every read
// would exempt it, and the line would be lost silently, forever.
//
// ⚠️ The file's own mtime is the evidence: a live process writes a line
// per call, so its file is touched constantly; a dead process's file has
// been still since it died. So a file that has been quiet for longer than
// this is not being written to any more.
//
// ⚠️ The pid in the file name would decide it exactly, but "is this pid
// alive" is not portable (Windows has no signal 0), and the difference
// between "exact" and "quiet for five minutes" does not change what a
// reader can do about it.
const halfWrittenGrace = 5 * time.Minute

func readStream(src io.Reader, opts ReadOptions, kept *newest, touched time.Time) (matched, skipped int, err error) {
	// ⚠️ The buffer is one byte LARGER than the limit: bufio's
	// ReadSlice gives up (ErrBufferFull) when the buffer is full and
	// no delimiter was found — so a buffer of exactly maxTrailLine
	// would skip a line whose content is exactly the limit. The
	// limit says "the longest line a read accepts", so that line
	// has to be accepted.
	r := bufio.NewReaderSize(src, maxTrailLine+1)
	for {
		line, rerr := r.ReadSlice('\n')
		if rerr == bufio.ErrBufferFull {
			// The line is longer than the reader's buffer: it is not
			// worth the memory, and the rest of the file is worth far
			// more. Skip this line — and whatever is left of it — and
			// carry on with the next one.
			//
			// ⚠️ Only the HEAD of the line is in hand here, and the head
			// is enough to tell whether the line could be about what the
			// caller asked for (see unreadableIsRelevant).
			if unreadableIsRelevant(string(line), opts) {
				skipped++
			}
			for rerr == bufio.ErrBufferFull {
				_, rerr = r.ReadSlice('\n')
			}
			if rerr == io.EOF {
				return matched, skipped, nil
			}
			if rerr != nil {
				return matched, skipped, rerr
			}
			continue
		}
		text := strings.TrimSpace(string(line))
		if text != "" {
			var e Entry
			if json.Unmarshal([]byte(text), &e) != nil {
				// ⚠️ A line that does not parse is a line the reader
				// could not take — and it has to be COUNTED.
				//
				// The third round of review counted the long lines and
				// left this one out, and the gap is the same gap in a
				// different place: the answer said "that is everything"
				// while a line was quietly gone. A broken line is a fact
				// about the trail's health, and the trail's health is
				// what the reader came for.
				//
				// ⚠️ But NOT the half-written LAST line: io.EOF means
				// there was no delimiter, so this line is still being
				// written. It is not broken, it is unfinished — and the
				// next read sees it whole. Counting it would cry wolf on
				// every read of a live trail.
				if !halfWritten(rerr, touched) && unreadableIsRelevant(text, opts) {
					skipped++
				}
			} else {
				// The moment is parsed ONCE and handed on: a filter
				// that had to parse it again would need a branch for
				// "the stamp cannot be read" — and that branch would
				// be dead code, because trailMoment already refused
				// such a line.
				at, ok := trailMoment(e)
				if ok && matches(e, at, opts) {
					matched++
					kept.add(e, at)
				}
			}
		}
		if rerr == io.EOF {
			return matched, skipped, nil
		}
		if rerr != nil {
			return matched, skipped, rerr
		}
	}
}

// halfWritten says whether the line at the end of the stream is one that
// is still being written.
//
// ⚠️ io.EOF with no delimiter means the stream ended mid-line. That is
// usually a line being written RIGHT NOW — but it is also what a process
// that was killed mid-write leaves behind, forever. The file's own mtime
// tells the two apart (see halfWrittenGrace).
func halfWritten(rerr error, touched time.Time) bool {
	return rerr == io.EOF && !touched.IsZero() && time.Since(touched) < halfWrittenGrace
}

// unreadableIsRelevant says whether a line the reader could NOT read could
// still be about what the caller asked for.
//
// ⚠️ A line that cannot be read cannot be filtered either — and the count
// of the unreadable lines is what the caller is told, so counting the
// lines that have nothing to do with the question is how a count becomes
// noise: an agent asking "which jmsx_exec calls were refused" used to see
// "one more line could not be read" because some OTHER tool's line was too
// long — and would then believe a refusal was missing.
//
// ⚠️ So the rule is: a line is counted unless it can be PROVED irrelevant.
// Only the columns at the HEAD of a line can be read out of a broken one
// (JSON puts them there first: ts, service, tool), and those are exactly
// the ones that say WHICH call the line is about. A line whose tool and
// service do not match the filters, or whose moment is before the window
// asked for, is about something else — and it is not counted.
//
// ⚠️ The other filters (client, allowed, refused, failed, delivery) are
// NOT consulted: they sit after the head, so a broken line cannot be read
// far enough to know them. A line that is about the right call but wrong in
// one of those is still counted — over-reporting is the harmless direction
// here, because the answer says "could not read", not "was refused".
func unreadableIsRelevant(text string, opts ReadOptions) bool {
	tool := jsonStringField(text, "tool")
	svc := jsonStringField(text, "service")
	ts := jsonStringField(text, "ts")
	if opts.Tool != "" && tool != "" && tool != opts.Tool {
		return false
	}
	if opts.Service != "" && svc != "" && svc != opts.Service {
		return false
	}
	if !opts.Since.IsZero() && ts != "" {
		if at, ok := parseTs(ts); ok && at.Before(opts.Since) {
			return false
		}
	}
	return true
}

// jsonStringFieldRE matches one string field of a line that may not be
// valid JSON.
//
// ⚠️ The closing quote is PART of the pattern, and that is the whole
// point: a value that was cut off mid-way has no closing quote, so it
// does not match, so the field reads as UNKNOWN. An earlier version
// accepted a half value — and a half value is not equal to the tool the
// caller asked about, so the line was judged "about something else" and
// NOT counted. A line cut in the middle of its tool name is exactly the
// line a caller most needs to hear about.
//
// ⚠️ The value may not contain a backslash: that keeps a JSON-escaped
// `"tool"` inside an argument from being read as the line's own field.
var jsonStringFieldRE = regexp.MustCompile(`"([^"\\]*)"\s*:\s*"([^"\\]*)"`)

// jsonStringField reads one string field out of a line that may not be
// valid JSON.
//
// ⚠️ It is deliberately a regexp and not a JSON decoder: the whole point
// is to read a field out of a line that CANNOT be decoded.
//
// ⚠️ It returns an empty string when the field is not there, when its
// value is cut off mid-way, or when the value holds a backslash — and an
// empty string means "unknown", so the caller treats the line as possibly
// relevant.
func jsonStringField(text, name string) string {
	for _, m := range jsonStringFieldRE.FindAllStringSubmatch(text, -1) {
		if m[1] == name {
			return m[2]
		}
	}
	return ""
}

// isTrailFact says whether a line is a fact about a call.
//
// Three things have to hold, and they are the same three the writer
// guarantees: the line is stamped at a moment we can place, it says which
// server wrote it, and it says which tool was called.
//
// ⚠️ The timestamp is the load-bearing one. A line whose stamp cannot be
// read cannot be placed in time — so it cannot answer "what happened
// since noon", and it cannot be ordered against the lines that can. One
// rule for both: a line that cannot be placed in time is not a fact about
// a moment, and the reader treats it as if it were not there. (The `Since`
// filter already had to skip such lines; the ORDERING now agrees with it,
// instead of quietly putting them at the end where they look like the
// oldest events in the trail.)
func trailMoment(e Entry) (time.Time, bool) {
	// ⚠️ The TOOL name is what makes a row a row; the SERVICE name is
	// not required. A row whose service is missing is still a fact about
	// a call — and the `service` filter copes with an empty one. Making
	// it a requirement would let one missing field make a whole
	// process's trail invisible, silently.
	if e.Tool == "" {
		return time.Time{}, false
	}
	return parseTs(e.Ts)
}

// matches says whether a line passes the filters.
func matches(e Entry, at time.Time, opts ReadOptions) bool {
	if opts.Service != "" && e.Service != opts.Service {
		return false
	}
	if opts.Tool != "" && e.Tool != opts.Tool {
		return false
	}
	if opts.Client != "" && e.Client != clientName(opts.Client) {
		return false
	}
	if opts.Allowed != nil && e.Allowed != *opts.Allowed {
		return false
	}
	if opts.Refused != nil && (e.Refused != "") != *opts.Refused {
		return false
	}
	if opts.Failed != nil && e.Failed != *opts.Failed {
		return false
	}
	if opts.Delivery != "" && e.Delivery != opts.Delivery {
		return false
	}
	if !opts.Since.IsZero() && at.Before(opts.Since) {
		return false
	}
	return true
}

// parseTs reads the stamp of a line.
func parseTs(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// modTime is when a file was last written, or the zero time when it cannot
// be read.
func modTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
