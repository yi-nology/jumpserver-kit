//go:build !windows

package audit

import (
	"errors"
	"syscall"
)

// processAlive says whether that process is still running.
//
// ⚠️ It is used by the pruning of the trail directory, and the question it
// answers is not academic: a file that belongs to a LIVE process must not
// be removed, because the process holds it open — removing the name would
// leave it writing into a file with no directory entry, and its trail
// would be gone, silently.
//
// ⚠️ It answers with THREE states, not two: "I cannot tell" must not be
// the same as "it is dead". Where the question cannot be answered (see
// alive_windows.go), the answer is AliveUnknown — and the caller then
// falls back to the mtime rules, which is what it did before the pid
// check existed.
//
// ⚠️ Signal 0 does not send anything: it only checks whether the process
// exists and whether we may signal it. EPERM means the process is there
// but belongs to somebody else ⇒ it counts as alive (we must not delete
// its file). ESRCH means it is gone.
func processAlive(pid int) AliveState {
	if pid <= 0 {
		return AliveDead
	}
	err := syscall.Kill(pid, 0)
	switch {
	case err == nil:
		return AliveYes
	case errors.Is(err, syscall.ESRCH):
		return AliveDead
	default:
		// EPERM and anything else: the process is there, we just may not
		// signal it.
		return AliveYes
	}
}
