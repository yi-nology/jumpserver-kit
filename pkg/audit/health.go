package audit

// health.go is the trail's own health check.
//
// ⚠️ It lives in the SHARED base and not in one server's doctor, because
// the two servers write the same trail directory BY DEFAULT — but the
// directory is CONFIGURABLE, and each server carries its own
// configuration. A check that exists in only one of them is a check the
// other one silently does not do: the management plane's trail could stop
// growing (its rotation failing) while the execution plane's doctor says
// everything is fine.
//
// Two copies of this check would drift, and the drifted one is the one
// that decides whether a broken trail is reported at all.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yi-nology/jumpserver-mcp-kit/model/jms"
	"github.com/yi-nology/jumpserver-mcp-kit/pkg/fspath"
)

// Reason says WHY the trail is not healthy.
//
// ⚠️ It is a separate value because a status is too coarse to carry the
// advice: four different things are a warning (nothing configured, the
// directory is not there yet, it cannot be read, a file is over the cap),
// and the advice for one of them is actively wrong for another — telling
// someone to go and free disk space when the real answer is "nothing is
// configured" is worse than saying nothing.
type Reason string

const (
	// ReasonNone means the trail is healthy.
	ReasonNone Reason = ""
	// ReasonOff means no trail directory is configured.
	ReasonOff Reason = "off"
	// ReasonMissing means the directory is not there yet.
	ReasonMissing Reason = "missing"
	// ReasonNotADir means the path is not a directory.
	ReasonNotADir Reason = "not-a-dir"
	// ReasonUnreadable means the directory could not be checked.
	ReasonUnreadable Reason = "unreadable"
	// ReasonOverCap means a file is over the cap: the rotation failed and
	// the file trail stopped there.
	ReasonOverCap Reason = "over-cap"
)

// writableProbe checks that the trail directory accepts a file.
//
// ⚠️ It writes a probe file and removes it, because "the directory exists"
// says nothing about whether the trail can be written — and the whole
// point of this check is to catch the case where the trail silently does
// not run.
//
// ⚠️ The probe file is EMPTY and is removed right away, so it is not a
// trail file and the reader never sees it.
func writableProbe(dir string) error {
	probe, err := os.CreateTemp(dir, ".jms-audit-probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name)
}

// trailDirShape says how many trail files the directory holds and how old
// the oldest one is.
//
// ⚠️ It only counts the files THIS package wrote (the same shape the
// reader recognises) ⇒ a neighbouring note is not counted as trail.
func trailDirShape(dir string) (files, oldest string) {
	paths, err := filepath.Glob(filepath.Join(dir, trailGlob))
	if err != nil {
		return "0 files", ""
	}
	n := 0
	var oldestTime time.Time
	for _, p := range paths {
		if !trailFileName.MatchString(filepath.Base(p)) {
			continue
		}
		n++
		if info, err := os.Stat(p); err == nil {
			if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
				oldestTime = info.ModTime()
			}
		}
	}
	if n == 0 {
		return "no trail files yet", ""
	}
	oldest = ""
	if !oldestTime.IsZero() {
		oldest = fmt.Sprintf(", the oldest from %s", oldestTime.Format("2006-01-02"))
	}
	return fmt.Sprintf("%d file(s)", n), oldest
}

// Advice says what to do about a trail that is not healthy.
//
// ⚠️ It lives here, in the shared base, because the two doctors have to
// give the SAME advice: the check is one check, and an advice that only
// one of them can give is advice half the operators never get.
//
// ⚠️ It is keyed on the REASON and not on the status: four different
// things are a warning (nothing configured, the directory is not there
// yet, it cannot be read or written, a file is over the cap), and the
// advice for one of them is actively wrong for another. Telling someone
// to go and free disk space when the real answer is "nothing is
// configured" sends them to the wrong place.
func Advice(reason Reason) string {
	switch reason {
	case ReasonOff:
		return "set JMS_AUDIT=file and point JMS_AUDIT_DIR at a directory this server can write to"
	case ReasonMissing:
		return "the trail directory is created when the server starts; if it does not appear, " +
			"check the path and the permissions"
	case ReasonNotADir:
		return "JMS_AUDIT_DIR points at something that is not a directory"
	case ReasonUnreadable:
		return "the trail directory could not be read or written: look at the path, the " +
			"permissions and whether the filesystem is read-only"
	case ReasonOverCap:
		return "the trail is not keeping up: check the free space on that filesystem — a file over " +
			"the cap means the rotation failed, and the file trail stopped there"
	default:
		return ""
	}
}

// CheckTrail says what the trail directory looks like from the operator's
// side.
//
// It answers one question: is the FILE trail actually running? The log
// line is written either way, so a trail that stopped on disk still leaves
// a trace in the log — but the log belongs to whoever started the process,
// and a host that does not keep it keeps nothing. That is the half that
// matters for a call that did NOT run.
//
// ⚠️ A check that cannot tell whether the trail is broken is NOT a passing
// check. Every branch below answers with a status, and none of them falls
// through to "ok".
func CheckTrail(dir string) (jms.Status, Reason, string) {
	dir = strings.TrimSpace(fspath.ExpandHome(dir))
	if dir == "" {
		return jms.Status_warn, ReasonOff, "no trail directory configured (JMS_AUDIT_DIR is empty)"
	}
	info, err := os.Stat(dir)
	switch {
	case err != nil:
		// ⚠️ Not every error means "it is not there yet": a directory the
		// process may not LOOK at (EACCES) is a different problem, and
		// telling the operator "it will be created when the server starts"
		// sends them the wrong way.
		if errors.Is(err, fs.ErrNotExist) {
			return jms.Status_warn, ReasonMissing, fmt.Sprintf(
				"the trail directory %s does not exist yet; it is created when the server starts", dir)
		}
		return jms.Status_warn, ReasonUnreadable, fmt.Sprintf(
			"the trail directory %s could not be checked: %v", dir, err)
	case !info.IsDir():
		return jms.Status_fail, ReasonNotADir, dir + " is not a directory"
	}
	// ⚠️ A directory that exists but cannot be WRITTEN to is a trail that
	// is OFF, and the old check called it "ok".
	//
	// The trail is one file per process, opened with O_APPEND; a
	// read-only or root-owned directory makes every write fail, the
	// writer logs one line and gives up — and from then on the process
	// keeps NO file trail at all, while the doctor says everything is
	// fine. That is the worst kind of answer an audit can give.
	if err := writableProbe(dir); err != nil {
		return jms.Status_fail, ReasonUnreadable, fmt.Sprintf(
			"the trail directory %s cannot be written to: %v", dir, err)
	}
	// ⚠️ An error from OverCap must NOT fall through to "ok": a check
	// that cannot tell whether the trail is broken is not a passing check.
	over, err := OverCap(dir)
	switch {
	case err != nil:
		return jms.Status_warn, ReasonUnreadable, fmt.Sprintf("the trail directory %s could not be checked: %v", dir, err)
	case len(over) > 0:
		// A file over the cap means the rotation did not happen, and the
		// writer stops the file trail when it cannot rotate. That is
		// worth saying out loud: the trail is still in the LOG from then
		// on, but the FILE stops growing.
		return jms.Status_warn, ReasonOverCap, fmt.Sprintf(
			"%d trail file(s) in %s are over the %d cap: the rotation failed and the file trail "+
				"stopped there (the log line still carries every call)",
			len(over), dir, MaxTrailBytes)
	default:
		// ⚠️ The SIZE of the directory is reported too: the trail is one
		// file per process, so the directory grows with the number of
		// restarts — and every query that scans it pays for the whole
		// history. An operator who sees 400 files should know why.
		files, oldest := trailDirShape(dir)
		return jms.Status_ok, ReasonNone, fmt.Sprintf(
			"%s (one JSONL file per process; read it with the jmsx_audit_query tool): %s",
			dir, files) + oldest
	}
}
