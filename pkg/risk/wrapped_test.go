package risk

import "testing"

// A destructive command does not become safe by being wrapped, substituted,
// piped or eval'd. These cases all used to classify as MODIFY — the
// confirmation gate asked nothing — because bashguard's Invocations only
// carry the outermost call:
//
//	sudo -n rm -rf /x        → {sudo, …}          judged "sudo"
//	nohup rm -rf /x          → {nohup, …}         judged "nohup"
//	true | rm -rf /x         → {true}             "rm" never seen at all
//	echo $(rm -rf /x)        → {echo, Dynamic}    "rm" hidden in a word
//
// Measured 2026-11-05; the AST walk in classify closes each of these.
func TestAWrappedDestructiveCommandIsStillDangerous(t *testing.T) {
	dangerous := []string{
		"sudo -n rm -rf /var/lib/x",
		"sudo -u root -n rm -rf /x",
		"sudo nohup rm -rf /x",
		"nohup rm -rf /x",
		"timeout 5 rm -rf /x",
		"timeout --signal=KILL 5 rm -rf /x",
		"env FOO=1 BAR=2 rm -rf /x",
		"env rm -rf /x",
		"xargs -I{} -0 rm -rf {} < list",
		"xargs rm -rf",
		"bash -c 'rm -rf /x'",
		"sh -c 'rm -rf /x'",
		"bash -c 'x=$(rm -rf /y); echo ok'",
		"echo $(rm -rf /x)",
		"echo `rm -rf /x`",
		"true | rm -rf /x",
		"eval \"rm -rf /x\"",
		"sudo -n systemctl reboot",
		"sudo -n mkfs.ext4 /dev/sda1",
		// Measured gaps closed 2026-11-06 (probe against Classify):
		"git push --force-with-lease origin main",
		"cat disk.img > /dev/sda",
		"./write.sh > /dev/mmcblk0",
	}
	for _, c := range dangerous {
		if got := Classify(c); got.String() != "DANGEROUS" {
			t.Errorf("%-44q = %s, want DANGEROUS", c, got)
		}
	}
}

// The peel must not swallow everyday commands: wrappers around harmless work
// stay exactly as permissive as they were, so the gate does not cry wolf.
func TestWrappersAroundHarmlessCommandsStayCalm(t *testing.T) {
	calm := map[string]string{
		"sudo -n systemctl restart nginx":       "MODIFY",
		"sudo -n true":                          "MODIFY",
		"timeout 10 sh -c 'curl -sf x | tar x'": "MODIFY",
		"env FOO=1 systemctl restart nginx":     "MODIFY",
		"xargs -I{} -0 chmod 644 {} < list":     "MODIFY",
		"nohup ./run.sh > log 2>&1 &":           "MODIFY",
		// bash -c stays MODIFY: bashguard does not prove wrapped CONTENT
		// read-only (a shell can run anything), so the outer command is
		// not proven safe — same as before the AST walk.
		"bash -c 'echo hello'":             "MODIFY",
		"echo hi | grep x":                 "READ",
		"env FOO=1 systemctl status nginx": "READ",
		"sudo -u root ls -la /var":         "MODIFY",
		// A dry run deletes nothing: over-asking on it taught the agent the
		// flag was meaningless (measured 2026-11-06).
		"kubectl delete --dry-run=client pod web-1": "MODIFY",
		// The everyday discards stay out of DANGEROUS — bashguard still
		// counts a redirect as a write (MODIFY), but the /dev/null and
		// /dev/zero exclusions keep them off the destructive list.
		"echo hi > /dev/null 2>&1":               "MODIFY",
		"cat /dev/zero | head -c 10 > /dev/null": "MODIFY",
	}
	for c, want := range calm {
		if got := Classify(c); got.String() != want {
			t.Errorf("%-44q = %s, want %s", c, got, want)
		}
	}
}
