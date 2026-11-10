package risk

import (
	_ "embed"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/oagentkit/tools/bashguard"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/syntax"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// readonlyTable is the fleet's read-only vocabulary.
//
//go:embed readonly.yaml
var readonlyTable []byte

// table is the read-only policy table: the analyzer's base table plus the
// commands this fleet's daily sweeps actually run.
//
// It is built once. DefaultTable() hands out a copy, and a classification
// happens on every command an agent runs.
var table = sync.OnceValue(buildTable)

// tableFile is the shape of readonly.yaml.
type tableFile struct {
	Version  int                    `yaml:"version"`
	Commands map[string]commandSpec `yaml:"commands"`
	// Excluded names commands REMOVED from the merged table (see the yaml
	// for why a name belongs here).
	Excluded []string `yaml:"excluded"`
}

// commandSpec is one command's entry.
//
// A subcommand list is deliberately a list of what is SAFE: the writing
// verbs are not mentioned, so they cannot be reached by a typo in a deny
// list.
type commandSpec struct {
	SafeFlags   map[string]string      `yaml:"safe_flags"`
	UnsafeFlags []string               `yaml:"unsafe_flags"`
	Subcommands map[string]commandSpec `yaml:"subcommands"`
}

// buildTable merges the analyzer's base table with the file's additions.
func buildTable() *bashguard.Table {
	t := bashguard.DefaultTable()

	var f tableFile
	if err := yaml.Unmarshal(readonlyTable, &f); err != nil {
		// The table is embedded, so a parse failure is a build-time
		// mistake, not a runtime condition. Refusing to classify anything
		// as read-only is the safe answer: the confirmation gate then
		// applies to every command.
		return t
	}
	for name, spec := range f.Commands {
		t.Commands[name] = spec.policy()
	}
	// 除名在合并之后：含 I/O 或执行原语的 mini-language（sed 的 w/W/e，
	// awk 的 system()/管道执行）不可能被证明只读，「listed = proven
	// read-only」的契约被破坏 ⇒ 从最终表里拽出去，让它们落进与其它
	// 未证明命令相同的 MODIFY 待遇（tools#81 + 下游同族排查）。
	for _, name := range f.Excluded {
		delete(t.Commands, name)
	}
	return t
}

// policy turns one entry into the analyzer's policy shape.
func (s commandSpec) policy() bashguard.Policy {
	p := bashguard.Policy{
		ReadOnly:    true,
		SafeFlags:   map[string]bashguard.FlagKind{},
		UnsafeFlags: s.UnsafeFlags,
	}
	for flag, kind := range s.SafeFlags {
		k, ok := flagKind(kind)
		if !ok {
			continue
		}
		p.SafeFlags[flag] = k
	}
	if len(s.Subcommands) > 0 {
		p.Subcommands = map[string]bashguard.Policy{}
		for name, sub := range s.Subcommands {
			p.Subcommands[name] = sub.policy()
		}
	}
	return p
}

// flagKind maps the file's spelling onto the analyzer's kinds.
func flagKind(s string) (bashguard.FlagKind, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bool":
		return bashguard.FlagBool, true
	case "string":
		return bashguard.FlagString, true
	case "number":
		return bashguard.FlagNumber, true
	case "optional":
		return bashguard.FlagOptional, true
	}
	return "", false
}

// Classify buckets a shell command so the caller (and the agent) can decide
// whether to run it, run it dry, or stop and ask.
func Classify(cmd string) jms.CommandClass {
	return classify(cmd, 0)
}

// classify is Classify with a recursion budget: shell -c strings and eval
// arguments are classified again, and peel chains (sudo nohup timeout …) walk
// inward, so the budget stops a pathological nest from looping forever.
func classify(cmd string, depth int) jms.CommandClass {
	if strings.TrimSpace(cmd) == "" {
		return jms.CommandClass_UNKNOWN
	}
	if depth > 6 {
		return jms.CommandClass_UNKNOWN
	}
	// ⚠️ 超长 ⇒ DANGEROUS（2026-11-09 实测的填充绕过，dry_run 验证）：
	// bashguard 对 >MaxCommandLen 的命令拒绝判定（AllCalls/Invocations 全空）
	// ⇒ 归 UNKNOWN ⇒ 不要求确认——而 `<10KB 注释填充>\n rm -rf /x` 恰好
	// 撑过长度闸，确认门被无声绕过。一个 >10KB 的 agent 脚本正是「该让人
	// 看一眼的东西」：拒绝判定的命令按 DANGEROUS 走（比例恰当，且判定
	// 缺席本身就是风险信号）。上游 tools#80 会给 Decision 加 OverLength
	// 标记，届时改为按标记判定。
	if len(cmd) > bashguard.MaxCommandLen {
		return jms.CommandClass_DANGEROUS
	}
	d := bashguard.Analyze(cmd, table())
	if d.ReadOnly {
		// The parser says this cannot write. That is the strongest
		// statement we can make without running it.
		return jms.CommandClass_READ
	}
	// The destructive judgement walks the WHOLE shell AST via upstream's
	// AllCalls (bashguard v0.12.0+, oagentkit/tools#35 — the field exists
	// precisely because this fleet used to hand-roll the same syntax.Walk):
	// Invocations only carries the outermost call, so a destructive command
	// wrapped in sudo/nohup/timeout/env/xargs, hidden in $(...) or a
	// backtick, or sitting in the second half of a pipeline used to sail
	// past the gate (measured: `sudo -n rm -rf /x` classified MODIFY — no
	// confirmation asked). Measured 2026-11-05.
	judged := false
	for _, c := range d.AllCalls {
		if c.Name == "" {
			// A dynamic command name ($VAR) says nothing about what runs.
			continue
		}
		judged = true
		if judgeInvocation(c.Name, c.Args, depth) {
			return jms.CommandClass_DANGEROUS
		}
	}
	if !judged && len(d.Invocations) == 0 {
		// Nothing was parsed: the command is too long, uses a construct the
		// parser refuses, or is empty. It is not proven safe.
		return jms.CommandClass_UNKNOWN
	}
	for _, inv := range d.Invocations {
		if destructive(inv, depth) {
			return jms.CommandClass_DANGEROUS
		}
	}
	// A redirect into a device file is the same write as `dd of=/dev/sda`,
	// which the table catches — `cat img > /dev/sda` sailed past it until
	// the walk looked at Stmt.Redirects (measured 2026-11-06).
	if dangerousRedirect(parsed(cmd)) {
		return jms.CommandClass_DANGEROUS
	}
	// It writes something, but nothing we know how to call irreversible.
	return jms.CommandClass_MODIFY
}

// parsed is the command's AST, or nil when it does not parse. classify's
// two consumers (dangerousRedirect here, upstream's Analyze inside
// bashguard) used to parse the same text twice — one parse, two readers.
func parsed(cmd string) *syntax.File {
	f, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil
	}
	return f
}

// dangerousRedirect reports whether the command aims an output redirect at
// a device file.
//
// `cat disk.img > /dev/sda` writes the boot disk exactly like `dd
// of=/dev/sda` — the table catches the dd spelling; the redirect spelling
// only shows up on the statement's Redirects, which Invocations never
// carried. /dev/null is excluded: discarding output is the everyday case,
// and /dev/zero discards writes the same way.
func dangerousRedirect(f *syntax.File) bool {
	if f == nil {
		return false
	}
	found := false
	syntax.Walk(f, func(n syntax.Node) bool {
		st, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		for _, r := range st.Redirs {
			if !strings.Contains(r.Op.String(), ">") {
				continue // an input redirect reads; only writes count
			}
			target, lit := wordLiteral(r.Word)
			if !lit {
				continue // a dynamic target ($DEV) says nothing about where
			}
			if strings.HasPrefix(target, "/dev/") &&
				target != "/dev/null" && target != "/dev/zero" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// wordLiteral is a word's spelling when every part of it is literal text.
func wordLiteral(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, p := range w.Parts {
		if !writePart(&b, p) {
			// ParamExp, CmdSubst, ArithmExp, ExtGlob … — dynamic.
			return "", false
		}
	}
	return b.String(), true
}

// writePart appends one word part when it is literal text; double quotes
// recurse because their contents are literal unless a $ or ` appears.
func writePart(b *strings.Builder, p syntax.WordPart) bool {
	switch t := p.(type) {
	case *syntax.Lit:
		b.WriteString(t.Value)
		return true
	case *syntax.SglQuoted:
		b.WriteString(t.Value)
		return true
	case *syntax.DblQuoted:
		for _, q := range t.Parts {
			if !writePart(b, q) {
				return false
			}
		}
		return true
	}
	return false
}

// judgeInvocation judges the command that will actually run: known wrappers
// are peeled (sudo, nohup, timeout, env, xargs, nice, stdbuf, setsid, exec,
// command), shells recurse into their -c string, and eval/exec execute their
// arguments as shell, so those arguments are classified again.
func judgeInvocation(name string, args []string, depth int) bool {
	name = baseName(name)
	// Shells: classify the script, not the shell.
	if isShell(name) {
		for i, a := range args {
			if a == "-c" && i+1 < len(args) {
				return RequiresConfirmation(classify(args[i+1], depth+1))
			}
		}
		return false
	}
	if name == "eval" && len(args) > 0 {
		// eval executes its arguments as shell text.
		return RequiresConfirmation(classify(strings.Join(args, " "), depth+1))
	}
	if real, rest, wrapped := peelWrapper(name, args); wrapped {
		return judgeInvocation(real, rest, depth+1)
	}
	// 「别处执行」的包装器（kit#26）：载荷不在本进程跑，而是进容器、进
	// 别的命名空间、切成别的用户——位置语义各不相同，所以按表取内层。
	if w, ok := peelElsewhere[name]; ok {
		if w.text != nil {
			if s := w.text(args); s != "" {
				return RequiresConfirmation(classify(s, depth+1))
			}
		} else if argv := w.argv(args); len(argv) > 0 {
			if argv[0] == "--" {
				argv = argv[1:] // 分隔符不是命令
			}
			if len(argv) > 0 {
				return judgeInvocation(argv[0], argv[1:], depth+1)
			}
		}
		// 内层定位不到（docker ps / su root 不带 -c）：按原样走下面的判定，
		// docker system prune / kubectl delete 仍在这里被抓住。
	}
	return destructive(bashguard.Invocation{Name: name, Args: args}, depth)
}

func isShell(name string) bool {
	switch name {
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		return true
	}
	return false
}

// peelValueFlags names the flags of each wrapper that consume the NEXT
// argument, so the peel lands on the command and not on a flag's value
// (`sudo -u root rm …` must not judge "root").
var peelValueFlags = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-T": true, "-r": true, "-t": true, "-U": true},
	"timeout": {"-k": true, "-s": true, "--kill-after": true, "--signal": true},
	"env":     {"-u": true, "-C": true, "-S": true},
	"xargs":   {"-I": true, "-L": true, "-n": true, "-P": true, "-s": true, "-d": true, "-E": true, "-e": true, "-i": true, "-l": true, "--replace": true, "--max-lines": true, "--max-args": true, "--max-procs": true, "--max-chars": true, "--delimiter": true, "--eof": true, "--arg-file": true},
	"nice":    {"-n": true, "--adjustment": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"ionice":  {"-c": true, "-n": true, "-p": true, "-u": true},
}

// peelBare names the wrappers whose arguments start at the first word that
// is not a flag.
var peelBare = map[string]bool{
	"nohup": true, "setsid": true, "exec": true, "command": true, "builtin": true,
}

// peelWrapper strips one wrapper layer. ok is false when name is not a
// wrapper (or carries no inner command), and the caller judges it as-is.
func peelWrapper(name string, args []string) (inner string, rest []string, ok bool) {
	vf, isWrapper := peelValueFlags[name]
	if !isWrapper && !peelBare[name] {
		return "", nil, false
	}
	i := skipFlags(args, vf)
	if name == "env" {
		// env VAR=val … cmd: the assignments are not the command either.
		for i < len(args) && isAssignment(args[i]) {
			i++
		}
	}
	if name == "timeout" && i < len(args) && isDuration(args[i]) {
		i++ // the duration is not the command
	}
	if i >= len(args) {
		return "", nil, false
	}
	return args[i], args[i+1:], true
}

// skipFlags walks an argument list past the wrapper's flags and returns the
// index of the first operand（值 flag 连值一起跳过，`--` 之后的都算操作数）。
// 剥壳机制共用的这一步原先内联在 peelWrapper 里；「别处执行」的包装器
// 各有自己的位置语义，但「跳过 flag、落在操作数上」是同一个动作。
func skipFlags(args []string, valueFlags map[string]bool) int {
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			return i + 1
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return i
		}
		if valueFlags[a] {
			i += 2 // 取值 flag 的值不是命令
			continue
		}
		i++
	}
	return i
}

// elsewhereRule 是「别处执行」包装器的内层定位规则：载荷跑在容器里、别的
// 命名空间里、别的用户下——包装器只是运输工具，破坏面在载荷上。argv 与
// text 二选一：argv 把载荷当命令+参数取出来；text 把载荷当 shell 文本
// （su -c 的串要递归 parse，不是 argv）。
type elsewhereRule struct {
	argv func(args []string) []string // nil = 该包装器的载荷不是 argv 形态
	text func(args []string) string   // 载荷的 shell 文本；空串 = 没有
}

// peelElsewhere 列出「载荷在别处执行」的包装器（kit#26）。这批包装器
// 违反了剥壳机制原来的假设「命令最终在本机进程里跑」：docker exec 把
// rm -rf 送进容器、nsenter -t 1 -m -- 直落宿主机根文件系统、chroot 换根、
// su -c 换用户——内层命令从来没进过判定，落点全在 MODIFY 免确认档。
// 定位不到内层时调用方按原样走 destructive()，所以 docker/kubectl 在
// 这里的既有判定（system prune / delete）不受影响。
var peelElsewhere = map[string]elsewhereRule{
	"docker":  {argv: containerInner},
	"podman":  {argv: containerInner},
	"nerdctl": {argv: containerInner},
	"kubectl": {argv: kubectlExecInner},
	"chroot":  {argv: chrootInner},
	"nsenter": {argv: func(args []string) []string { return args[skipFlags(args, nsenterValueFlags):] }},
	"su":      {text: suShellText},
	"systemd-run": {
		argv: func(args []string) []string { return args[skipFlags(args, systemdRunValueFlags):] },
	},
	"watch": {argv: func(args []string) []string { return args[skipFlags(args, watchValueFlags):] }},
}

// 各「别处执行」包装器里消耗下一个参数的 flag：定位内层时跳过值，否则
// 值会被误当容器名 / 镜像 / 命令（`docker run -v /:/host alpine rm …` 把
// /:/host 当了镜像，真命令就整体判错位）。等号形态（--user=root）是单
// token，通用路径自会跳过。
var (
	containerValueFlags = map[string]bool{
		// docker/podman exec 与 run 的并集——run 的取值 flag 远多于 exec
		//（卷、端口、资源、网络、健康检查……）。
		"-u": true, "--user": true, "-w": true, "--workdir": true,
		"-e": true, "--env": true, "--env-file": true,
		"-v": true, "--volume": true, "--mount": true, "--name": true,
		"-p": true, "--publish": true, "--expose": true, "--link": true,
		"--network": true, "--net": true, "--mac-address": true, "--ip": true,
		"--dns": true, "--dns-search": true, "--dns-option": true, "--add-host": true,
		"-h": true, "--hostname": true, "--domainname": true,
		"-m": true, "--memory": true, "--memory-swap": true, "--memory-reservation": true,
		"--cpus": true, "--cpu-shares": true, "-c": true, "--cpu-period": true, "--cpu-quota": true,
		"--restart": true, "--runtime": true, "--platform": true, "--pull": true,
		"--entrypoint": true, "-l": true, "--label": true, "--label-file": true,
		"--cap-add": true, "--cap-drop": true, "--device": true, "--device-cgroup-rule": true,
		"--gpus": true, "--group-add": true, "--health-cmd": true, "--health-interval": true,
		"--health-retries": true, "--health-timeout": true, "--health-start-period": true,
		"--log-driver": true, "--log-opt": true, "--shm-size": true, "--stop-signal": true,
		"--stop-timeout": true, "--ulimit": true, "--sysctl": true, "--tmpfs": true,
		"--volumes-from": true, "--security-opt": true, "--storage-opt": true,
		"--cgroup-parent": true, "--pid": true, "--ipc": true, "--uts": true, "--userns": true,
		"-a": true, "--attach": true, "--cidfile": true,
	}
	kubectlExecValueFlags = map[string]bool{
		"-c": true, "--container": true, "-n": true, "--namespace": true,
		"--context": true, "--kubeconfig": true, "--cluster": true, "--user": true,
		"--pod": true, "--pod-name": true,
	}
	chrootValueFlags = map[string]bool{
		"--userspec": true, "--user": true, "-u": true, "--groups": true, "-g": true,
	}
	nsenterValueFlags = map[string]bool{
		"-t": true, "--target": true, "-S": true, "--setuid": true, "-G": true, "--setgid": true,
	}
	systemdRunValueFlags = map[string]bool{
		"--unit": true, "--property": true, "-p": true, "--description": true,
		"--slice": true, "--setenv": true, "-E": true, "--uid": true, "--gid": true,
		"--nice": true, "--working-directory": true, "--tty": true,
	}
	watchValueFlags = map[string]bool{
		"-n": true, "--interval": true,
	}
)

// containerInner 定位 docker/podman/nerdctl 的内层命令：
//
//	exec  [-flags] CONTAINER CMD…（container exec 同形）
//	run   [-flags] IMAGE    CMD…
//
// 第一个非 flag 操作数是容器/镜像，命令在它之后；之后没有词 = 没带命令
// （docker run -it alpine），按原样走调用方的判定。
func containerInner(args []string) []string {
	rest := args
	if len(rest) > 1 && rest[0] == "container" && rest[1] == "exec" {
		rest = rest[1:]
	}
	if len(rest) < 2 || (rest[0] != "exec" && rest[0] != "run") {
		return nil
	}
	j := skipFlags(rest[1:], containerValueFlags)
	if j+1 >= len(rest[1:]) {
		return nil
	}
	return rest[j+2:]
}

// kubectlExecInner 定位 kubectl exec 的内层命令：`--` 之后是规范形态；
// 无 `--` 时 flags → pod 名 → 命令。kubectl 的全局 flag（-n/--context…）
// 允许写在 exec 前面，先跳过再认子命令。
func kubectlExecInner(args []string) []string {
	rest := args
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		if kubectlExecValueFlags[rest[0]] && len(rest) > 1 {
			rest = rest[2:]
			continue
		}
		rest = rest[1:]
	}
	if len(rest) == 0 || rest[0] != "exec" {
		return nil
	}
	for i, a := range rest[1:] {
		if a == "--" {
			return rest[i+2:]
		}
	}
	j := skipFlags(rest[1:], kubectlExecValueFlags)
	if j+1 >= len(rest[1:]) {
		return nil
	}
	return rest[j+2:]
}

// chrootInner：NEWROOT 是第一个操作数，命令是第二个；只有 NEWROOT 没有
// 命令 = 进去起交互 shell，没有可判的内层。
func chrootInner(args []string) []string {
	j := skipFlags(args, chrootValueFlags)
	if j+1 >= len(args) {
		return nil
	}
	return args[j+1:]
}

// suShellText 取 su -c/--command 的值：那是一段 shell 文本，交给 classify
// 递归分类（`su - root -c 'rm -rf /data'` 的载荷在引号里，不是 argv）。
func suShellText(args []string) string {
	for i, a := range args {
		if a == "-c" || a == "--command" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if s, ok := strings.CutPrefix(a, "--command="); ok {
			return s
		}
	}
	return ""
}

func isAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := s[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func isDuration(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	if i < len(s) {
		switch s[i] {
		case 's', 'm', 'h', 'd':
			i++
		}
	}
	return i == len(s)
}

// RequiresConfirmation reports whether a command of this class has to be
// confirmed before it runs.
//
// Only DANGEROUS does. UNKNOWN is not escalated, and that is a deliberate
// trade-off: the classifier cannot place every command, so asking for a
// confirmation on everything it does not recognise would make the flag
// meaningless (the agent would set it without reading it).
//
// The flag is a speed bump, not a security boundary — the agent can always
// confirm. What it buys is that the destructive commands are the ones the
// agent has to think about.
func RequiresConfirmation(c jms.CommandClass) bool {
	return c == jms.CommandClass_DANGEROUS
}

// Rehearsal answers the question every dry run and every refusal answers
// the same way: would this command run, and if not, what is missing?
//
// A command runs when it needs no confirmation, or when the confirmation
// is already there. When it would not run, the answer carries the one
// sentence that tells the caller what to do about it.
//
// ⚠️ The WORDING is a cross-server contract: the management plane and the
// execution plane answer the same question ("would this run?"), and an
// agent that reads one of them has to read the other the same way. The
// sentence is built HERE, once — the planes each used to spell it for
// themselves, and one of them hard-coded "DANGEROUS" into a sentence that
// was supposed to name the class it actually found.
func Rehearsal(c jms.CommandClass, confirmed bool) (would bool, blocked string) {
	would = !RequiresConfirmation(c) || confirmed
	if !would {
		blocked = "classified " + c.String() + "; re-call with confirm=true to execute"
	}
	return would, blocked
}

// destructive reports whether one invocation is irreversible.
//
// The rules are on the command NAME and its arguments, because that is what
// the parser gives: the name of the program and its arguments. A dangerous
// word inside a string is not a command, and a dangerous command behind a
// wrapper (sudo, nohup, timeout) is still the same command.
//
// ⚠️ 双源约定（kit#24 顺带核实的那条）：上游 bashguard 已经算出
// Decision.Destructive，本函数**不消费**它——kit 自维护一张刻意更宽的
// 表（剥壳、mini-language 深检、find 的内层重判都宽过上游），上游表补
// 齐之前复用它只会窄化判定。漂移的门禁是本包的钉测试：每条「宽过上游」
// 的行为都有对应用例，上游追平与否在这里可见、可决策。
//
// depth 是递归预算：find -exec 的内层命令会再走一次判定（与 sudo/xargs
// 剥壳同一条纪律），预算由 classify 收口。
func destructive(inv bashguard.Invocation, depth int) bool {
	name := baseName(inv.Name)
	args := inv.Args
	// mini-language 深检（excluded 的后半段）：除名只把 sed/awk 拽出 READ
	// 档，落进 MODIFY——而 MODIFY 照旧免确认。带着写/执行原语的脚本必须
	// 在这里被判 DANGEROUS，否则 sed 's/x/y/e'（任意命令执行）会与
	// sed 's/a/b/'（纯文本过滤）走同一条免确认车道。
	if miniLanguageDanger(name, args) {
		return true
	}
	switch {
	case name == "rm":
		// A recursive delete is the classic one. `rm -f file` is not.
		return hasFlag(args, "-r", "-R", "--recursive")
	case strings.HasPrefix(name, "mkfs"):
		return true
	case name == "wipefs", name == "shred":
		return true
	case name == "dd":
		// Writing to a device: dd if=... of=/dev/sda
		for _, a := range args {
			if strings.HasPrefix(a, "of=") {
				return true
			}
		}
		return false
	case name == "reboot", name == "shutdown", name == "poweroff", name == "halt", name == "kexec":
		return true
	case name == "init":
		// init 0 / init 6
		return slices.Contains(args, "0") || slices.Contains(args, "6")
	case name == "userdel", name == "useradd", name == "usermod",
		name == "groupdel", name == "groupadd", name == "passwd", name == "chpasswd",
		name == "gpasswd", name == "visudo":
		// Account and privilege changes: they are how someone gets in, and
		// undoing one is not in the tool's hands.
		return true
	case name == "systemctl":
		for _, a := range args {
			switch a {
			case "disable", "mask", "poweroff", "reboot", "halt", "kexec":
				return true
			}
		}
		return false
	case name == "iptables", name == "ip6tables":
		// -F/--flush 清链上的规则；-X/--delete-chain 删链——链上规则一并
		// 消失且不可撤销（kit#25：-X 不在判定表里，免确认就下发了）。
		return hasFlag(args, "-F", "--flush", "-X", "--delete-chain")
	case name == "nft":
		// nft 的语法是子命令式的：delete/flush 直接抹掉 table/chain/rule
		//（`nft flush ruleset` 一句清空整张防火墙）。list 系照旧不在此列。
		return slices.Contains(args, "delete") || slices.Contains(args, "flush")
	case name == "chmod", name == "chown":
		// `chmod -R 777 /` reaches everything; `chmod 644 file` does not.
		return hasFlag(args, "-R", "--recursive")
	case name == "kill", name == "killall", name == "pkill":
		// 单 token 带齐信号的形态：-9 / -KILL / -SIGKILL / --signal=KILL。
		if hasFlag(args, "-9", "-KILL", "-SIGKILL", "--signal") {
			return true
		}
		// 分离形态（kit#23）：`kill -s KILL <pid>`——信号名在下一个
		// token 上，POSIX 写法，原先不在表里。pkill 的 -s 是 session，
		// 它只有 --signal，不在这里判。
		if name == "pkill" {
			return false
		}
		for i := 0; i+1 < len(args); i++ {
			if (args[i] == "-s" || args[i] == "--signal") && isKillSignal(args[i+1]) {
				return true
			}
		}
		return false
	case name == "journalctl":
		// Vacuuming the journal deletes the audit trail.
		return hasFlag(args, "--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush")
	case name == "find":
		// find 的批量删除形态（kit#24）：-delete 对每个命中直接 unlink，
		// 与 rm -rf 同破坏面；-exec/-execdir 对每个命中执行一条任意命令
		// ——与 sudo/xargs 兜底同一条纪律：跳过 {} 占位与 ; / + 终结符，
		// 把内层命令再走一次判定。
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "-delete":
				return true
			case "-exec", "-execdir":
				inner, consumed, ok := findExecBody(args[i+1:])
				if !ok {
					// 没有终结符：这条 find 自己跑不起来，内层不可定位
					// ——按危险走（宁枉勿纵）。
					return true
				}
				if len(inner) > 0 && judgeInvocation(inner[0], inner[1:], depth+1) {
					return true
				}
				i += consumed // 内层体消费掉，别把载荷的词再当 find 参数扫
			}
		}
		return false
	case name == "kubectl":
		// A dry run deletes nothing — asking for a confirmation on it
		// teaches the agent that the flag is meaningless (measured
		// 2026-11-06: `--dry-run=client` classified DANGEROUS).
		for _, a := range args {
			if a == "--dry-run" || strings.HasPrefix(a, "--dry-run=") {
				return false
			}
		}
		return slices.Contains(args, "delete")
	case name == "docker", name == "podman":
		for i, a := range args {
			if a == "system" && i+1 < len(args) && args[i+1] == "prune" {
				return true
			}
		}
		return false
	case name == "git":
		return destructiveGit(args)
	}
	// The uninstall scripts are destructive by name.
	return strings.HasSuffix(name, "-uninstall.sh")
}

// ── mini-language 深检（sed / awk）──────────────────────────────

// miniLanguageDanger inspects the SCRIPT CONTENT of the two demoted
// mini-languages (see readonly.yaml's excluded for why they left the
// read-only table). sed 和 awk 是带 I/O 与执行原语的图灵完备小语言：
// 「命令名是过滤器」证明不了「这次调用是过滤器」——判定要看脚本。
func miniLanguageDanger(name string, args []string) bool {
	switch baseName(name) {
	case "sed":
		return sedScriptDanger(args)
	case "awk", "gawk", "mawk":
		return awkProgramDanger(args)
	}
	return false
}

// 措辞级探测，宁枉勿纵：误报的代价是一次确认，漏报的代价是一次免确认
// 的执行。上游给 bashguard 补上脚本解析（tools#81）后可收紧精度。
var (
	// sedWriteRe 抓 w/W 写文件：行地址形态（1w f、/re/w f、2,5w f）与
	// s///w 尾旗都落在这里——w 前允许数字、$/、分隔符，只排除字母与
	// 反斜杠（排除字母会把 '1w' 漏掉，排除数字会把地址形态漏掉）。
	sedWriteRe = regexp.MustCompile(`(?:^|[^\\a-zA-Z])[wW]\s+\S`)
	// sedExecRe 抓裸 e 命令与 s///e 尾旗（把替换结果当 shell 跑）：
	// e 后必须是空白或串尾——'s/eval/e/' 里被替换文本中的 e 后面跟着
	// 分隔符，不命中。
	sedExecRe = regexp.MustCompile(`(?:^|[^\\a-zA-Z])e(?:\s|$)`)
)

// sedScriptDanger collects sed's script operands（-e/--expression 的值与
// 裸操作数）逐段探测；脚本在文件里（-f/--file）内容不可见，证明不了
// 无写——按危险走。
func sedScriptDanger(args []string) bool {
	var scripts []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || a == "--file" || strings.HasPrefix(a, "--file="):
			return true
		case a == "-e" || a == "--expression":
			if i+1 < len(args) {
				scripts = append(scripts, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--expression="):
			scripts = append(scripts, strings.TrimPrefix(a, "--expression="))
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// 其余 flag（含 -En 这类短旗捆绑）：不含脚本。
		default:
			scripts = append(scripts, a)
		}
	}
	for _, s := range scripts {
		if sedWriteRe.MatchString(s) || sedExecRe.MatchString(s) {
			return true
		}
	}
	return false
}

// awkProgramDanger scans the awk program text for its exec/write
// primitives: system()、单竖线管道（print | "cmd"、cmd | getline——剔除
// || 与 && 后再找竖线）、print 重定向到带引号文件名（> "f" / >> "f"；
// 数值比较 $3 > 100 不带引号，不命中）。程序在文件里（-f/-E/-i/-p/-o
// 系）内容不可见——按危险走。
func awkProgramDanger(args []string) bool {
	awkFileFlags := map[string]bool{
		"-f": true, "--file": true, "-E": true, "--exec": true,
		"-i": true, "--include": true, "-p": true, "--profile": true,
		"-o": true, "--pretty-print": true,
	}
	prog := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if awkFileFlags[a] || (len(a) > 2 && strings.HasPrefix(a, "-f")) {
			// -f 的捆绑短形（-fprog.awk）与全名都算脚本文件。
			return true
		}
		switch {
		case a == "-e":
			if i+1 < len(args) {
				prog = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// 其余 flag：-v/--assign、-F 取值要跳过它们的值。
			if i+1 < len(args) && !strings.Contains(a, "=") {
				// 保守跳过下一个词当值——只有 -v/-F/--assign 需要跳，
				// 其它（如 --）误跳一个词也无碍（程序多为裸操作数）。
				i++
			}
		default:
			if prog == "" {
				prog = a // awk 的第一个裸操作数是程序
			}
		}
	}
	if prog == "" {
		return false
	}
	if strings.Contains(prog, "system(") {
		return true
	}
	// 单竖线：剔除逻辑或/与后再找管道（|| 与 && 是常见 benign 组合）。
	if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(prog, "||", ""), "&&", ""), "|") {
		return true
	}
	if regexp.MustCompile(`>\s*["']`).MatchString(prog) {
		return true
	}
	return false
}

// destructiveGit is the git subset that throws work away.
func destructiveGit(args []string) bool {
	for _, a := range args {
		switch a {
		case "clean":
			// git clean -fd（捆绑短旗同样带 f：hasFlag 认三种拼写）
			return hasFlag(args, "-f", "--force")
		case "reset":
			// git reset --hard
			return hasFlag(args, "--hard")
		case "push":
			// git push --force — and --force-with-lease, which overwrites
			// the remote the same way when the lease passes (it exists to
			// be run where --force would be; measured 2026-11-06:
			// --force-with-lease classified MODIFY, a silent bypass).
			return hasFlag(args, "-f", "--force", "--force-with-lease", "--force-if-includes")
		case "filter-branch":
			return true
		}
	}
	return false
}

// baseName is the program's name without its directory.
//
// A path is still a program: /usr/bin/rm is rm.
func baseName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// hasFlag reports whether one of the flags is present, in any of the three
// spellings the command line allows:
//
//   - exact:             -f   --force
//   - bundled shorts:    -fdx carries -f（短旗可捆绑，rm -rf 早就如此）
//   - long with a value: --hard=HEAD~1 carries --hard
//
// 精确相等是旧规则，它把同一个动作按拼写分了两档：`git clean -f -d -x`
// 要确认而 `git clean -fdx`——更自然的写法——免确认直过（kit#23）。
// 误报方向是安全的：一次多余的确认；漏报方向是一次免确认的不可逆执行。
func hasFlag(args []string, flags ...string) bool {
	for _, a := range args {
		if len(a) < 2 || a[0] != '-' {
			continue // not a flag
		}
		if a[1] == '-' {
			// 长旗：--hard=HEAD~1 载有 --hard。
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				a = a[:eq]
			}
			if slices.Contains(flags, a) {
				return true
			}
			continue
		}
		// 短旗或一捆短旗：-fdx 载有 -f。
		for _, f := range flags {
			if len(f) == 2 && f[0] == '-' && strings.ContainsRune(a[1:], rune(f[1])) {
				return true
			}
		}
	}
	return false
}

// isKillSignal 报告 token 是否指名 SIGKILL（信号名 / SIG 前缀形态 / 编号）。
// kill -s 的信号在下一个 token 上，得看值而不是 flag 本身。
func isKillSignal(s string) bool {
	s = strings.TrimPrefix(strings.ToUpper(s), "SIG")
	return s == "KILL" || s == "9"
}

// findExecBody 收集 -exec/-execdir 到它的 ; / + 终结符之间的命令（{}
// 是 find 填充的占位符，属数据不属命令词），返回去占位后的命令与消耗的
// 参数个数。ok=false：没有终结符——这条 find 自己跑不起来，内层不可定位。
// 终结符的 `\;` 形态：shell 里 ; 必须转义，parser 把字面量连同反斜杠
// 一起交下来（实测 AllCall 的 args 是 `\;` 两字符）。
func findExecBody(args []string) (cmd []string, consumed int, ok bool) {
	for j, a := range args {
		if a == ";" || a == "\\;" || a == "+" {
			return cmd, j + 1, true
		}
		if a == "{}" {
			continue
		}
		cmd = append(cmd, a)
	}
	return nil, 0, false
}
