//go:build windows

package audit

// processAlive says whether that process is still running.
//
// ⚠️ On Windows there is no signal 0 — Process.Signal only supports Kill —
// so the question cannot be answered. The answer used here is "yes", which
// is the CONSERVATIVE one: a file that might belong to a live process is
// left alone, and the directory is pruned a little less eagerly.
//
// ⚠️ The consequence is that on Windows a file of a LIVE process is not
// protected by the pid rule — but the mtime rules still apply (the empty
// rule and the retention rule), so the directory is still bounded.
//
// ⚠️ ⚠️ It used to answer "alive" for everything, which SHORT-CIRCUITED
// both mtime rules ⇒ on Windows the directory was NEVER pruned at all.
// That was a false statement in the code comment and in the
// documentation, and the unit test caught it as soon as the Windows
// implementation was run on this machine.
func processAlive(pid int) AliveState {
	return AliveUnknown
}
