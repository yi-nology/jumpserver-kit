package risk

import (
	"testing"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// 不可逆动作不得因为「换一种拼写」就换档（kit#23）。命令行允许的三种
// 形态——规范拼写、捆绑短旗、等号长旗——必须同档：`git clean -f -d -x`
// 与 `git clean -fdx` 是同一个动作，前者要确认而后者免确认直过，等于给
// 执行面开了一条稳定的免确认旁路（实测 2026-11-09/10，四族命令同根因：
// hasFlag 的精确匹配）。
func TestIrreversibleFlagSpellingsStayOneClass(t *testing.T) {
	cases := []struct {
		cmd  string
		want jms.CommandClass
	}{
		// git：规范 / 捆绑 / 等号 三种拼写同档。
		{"git clean -f -d -x", jms.CommandClass_DANGEROUS},
		{"git clean -fdx", jms.CommandClass_DANGEROUS},
		{"git clean -fd", jms.CommandClass_DANGEROUS},
		{"git clean -f", jms.CommandClass_DANGEROUS},
		{"git push -f origin main", jms.CommandClass_DANGEROUS},
		{"git push -fu origin main", jms.CommandClass_DANGEROUS},
		{"git reset --hard HEAD~1", jms.CommandClass_DANGEROUS},
		{"git reset --hard=HEAD~1", jms.CommandClass_DANGEROUS},

		// journalctl：文档里唯一被接受的写法就是等号形态——清审计日志
		// 的不可逆操作曾因此落进免确认车道。
		{"journalctl --vacuum-size=1G", jms.CommandClass_DANGEROUS},
		{"journalctl --vacuum-size 1G", jms.CommandClass_DANGEROUS},
		{"journalctl --vacuum-time=2weeks", jms.CommandClass_DANGEROUS},
		{"journalctl --vacuum-files=100", jms.CommandClass_DANGEROUS},

		// kill：信号名单独一个 token 的 POSIX 分离形态。
		{"kill -s KILL 1234", jms.CommandClass_DANGEROUS},
		{"kill -s 9 1234", jms.CommandClass_DANGEROUS},
		{"kill --signal=KILL 1234", jms.CommandClass_DANGEROUS},
		{"killall -s KILL nginx", jms.CommandClass_DANGEROUS},
		{"pkill --signal=KILL nginx", jms.CommandClass_DANGEROUS},

		// chmod/chown：GNU 允许模式与短旗捆绑（-R755 = -R 755）。
		{"chmod -R755 /etc", jms.CommandClass_DANGEROUS},
		{"chown -R777 /", jms.CommandClass_DANGEROUS},
		{"chmod --recursive=755 /etc", jms.CommandClass_DANGEROUS},

		// 对照组：可逆的近邻拼写不升级——捆绑感知不得变成按首字母猜。
		{"git clean -n -d", jms.CommandClass_MODIFY},                    // dry-run
		{"git push -u origin main", jms.CommandClass_MODIFY},            // 只设上游
		{"git push --follow-tags origin main", jms.CommandClass_MODIFY}, // 不含 f 的长旗
		{"kill -s TERM 1234", jms.CommandClass_MODIFY},                  // 温和信号
		{"kill -l", jms.CommandClass_MODIFY},                            // 列信号名
		{"chmod 644 /etc/app.conf", jms.CommandClass_MODIFY},
		{"chown bob /data/file", jms.CommandClass_MODIFY},
		{"journalctl -u nginx --since '1 hour ago'", jms.CommandClass_READ},
	}
	for _, c := range cases {
		if got := Classify(c.cmd); got != c.want {
			t.Errorf("Classify(%q) = %s, want %s", c.cmd, got, c.want)
		}
	}
}

// find 的两种批量删除形态与 rm -rf 同破坏面，不得落 MODIFY 免确认档
// （kit#24）。-exec 的内层命令按 sudo/xargs 同一条纪律重判：内层是 rm
// 就危险，是 grep 就照旧免确认——不是见到 -exec 就一票否决。
func TestFindDeleteAndExecCarryTheRmBlastRadius(t *testing.T) {
	cases := []struct {
		cmd  string
		want jms.CommandClass
	}{
		{"find . -delete", jms.CommandClass_DANGEROUS},
		{"find / -name '*.log' -delete", jms.CommandClass_DANGEROUS},
		{"find . -exec rm -rf {} +", jms.CommandClass_DANGEROUS},
		{"find . -execdir rm -rf {} +", jms.CommandClass_DANGEROUS},
		{"find . -name core -exec sudo rm -rf {} \\;", jms.CommandClass_DANGEROUS},
		{"find /var -type f -exec shred {} \\;", jms.CommandClass_DANGEROUS},
		{"find . -name x -exec sh -c 'rm -rf /data' \\;", jms.CommandClass_DANGEROUS},
		{"rm -rf /x", jms.CommandClass_DANGEROUS}, // 同档锚点

		// 对照组：内层可逆、无删除谓词的 find 不升级（只读形态上游表
		// 已证明：find 纯查询 = READ）。
		{"find . -name '*.log'", jms.CommandClass_READ},
		{"find . -name core -exec gzip {} \\;", jms.CommandClass_MODIFY},
		{"find . -maxdepth 1 -type f -exec ls -la {} \\;", jms.CommandClass_MODIFY},
	}
	for _, c := range cases {
		if got := Classify(c.cmd); got != c.want {
			t.Errorf("Classify(%q) = %s, want %s", c.cmd, got, c.want)
		}
	}
}

// iptables -X 与 -F 同级（kit#25）：删链把链上全部规则一并抹掉且不可
// 撤销，还是删除用户自定义链的唯一手段。nft 的子命令式语法（delete /
// flush）单独核过——不能只加 iptables 的 token。
func TestChainAndRuleWipeSpellingStayOneClass(t *testing.T) {
	cases := []struct {
		cmd  string
		want jms.CommandClass
	}{
		{"iptables -F", jms.CommandClass_DANGEROUS},
		{"iptables -X CUSTOM", jms.CommandClass_DANGEROUS},
		{"iptables --delete-chain CUSTOM", jms.CommandClass_DANGEROUS},
		{"iptables -t nat -X DOCKER", jms.CommandClass_DANGEROUS},
		{"ip6tables -X CUSTOM", jms.CommandClass_DANGEROUS},
		{"nft flush ruleset", jms.CommandClass_DANGEROUS},
		{"nft flush chain inet filter input", jms.CommandClass_DANGEROUS},
		{"nft delete table inet filter", jms.CommandClass_DANGEROUS},
		{"nft delete chain inet filter input", jms.CommandClass_DANGEROUS},
		{"nft delete rule inet filter input", jms.CommandClass_DANGEROUS},

		// 对照组：加规则 / 查询不升级。
		{"iptables -t filter -A INPUT -j ACCEPT", jms.CommandClass_MODIFY},
		{"iptables -L", jms.CommandClass_MODIFY},
		{"nft list ruleset", jms.CommandClass_MODIFY},
	}
	for _, c := range cases {
		if got := Classify(c.cmd); got != c.want {
			t.Errorf("Classify(%q) = %s, want %s", c.cmd, got, c.want)
		}
	}
}

// 「在别处执行」的包装器（kit#26）：容器、命名空间、切用户、systemd
// 单元、循环。剥壳机制原来假设命令最终在本机进程里跑——docker exec /
// kubectl exec / chroot / nsenter / su -c 全都违反这个假设，内层 rm -rf
// 从没进过判定，免确认就下发给堡垒机。每个包装器至少一条「内层 rm -rf
// ⇒ DANGEROUS」断言，加日常对照组防止改坏。
func TestElsewhereExecutedPayloadsAreJudged(t *testing.T) {
	dangerous := []string{
		"docker exec web rm -rf /data",
		"docker exec -it web sh -c 'rm -rf /'",
		"docker exec -u root web rm -rf /data",
		"docker run --rm -v /:/host alpine rm -rf /host/data",
		"docker container exec web rm -rf /data",
		"podman exec web rm -rf /data",
		"nerdctl exec web rm -rf /data",
		"kubectl exec pod-1 -- rm -rf /data",
		"kubectl exec -it pod-1 -- sh -c 'rm -rf /'",
		"kubectl exec -n prod pod-1 -- rm -rf /data",
		"kubectl -n prod exec pod-1 -- rm -rf /data",
		"chroot /host /bin/rm -rf /data",
		"nsenter -t 1 -m -- rm -rf /data",
		"nsenter -t 1 -m rm -rf /data",
		"su - root -c 'rm -rf /data'",
		"su root -c 'rm -rf /data'",
		"su -c 'mkfs.ext4 /dev/sda1'",
		"systemd-run --unit=x /bin/rm -rf /data",
		"watch -n 1 rm -rf /data",
		"sudo nsenter -t 1 -m -- rm -rf /data", // 与既有剥壳叠加
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS", cmd, got)
		}
	}

	// 对照组：载荷可逆 / 无载荷的形态不升级——剥壳不许带来新摩擦。
	calm := map[string]jms.CommandClass{
		"docker exec web ls /data":                  jms.CommandClass_MODIFY,
		"docker run --rm alpine echo hi":            jms.CommandClass_MODIFY,
		"docker run -d -p 8080:80 --name web nginx": jms.CommandClass_MODIFY,
		"docker ps":                      jms.CommandClass_READ,
		"docker system prune -af":        jms.CommandClass_DANGEROUS, // 既有判定不丢
		"kubectl exec pod-1 -- ls /data": jms.CommandClass_MODIFY,
		"kubectl delete pod web-1":       jms.CommandClass_DANGEROUS, // 既有判定不丢
		"kubectl get pods":               jms.CommandClass_READ,
		"chroot /host":                   jms.CommandClass_MODIFY, // 只换根起 shell
		"su - root":                      jms.CommandClass_MODIFY, // 交互 shell，无 -c 载荷
		"su -c 'uptime'":                 jms.CommandClass_MODIFY, // 载荷只读
		"watch -n 1 uptime":              jms.CommandClass_MODIFY,
		"sudo -n rm -rf /x":              jms.CommandClass_DANGEROUS, // 既有剥壳不回归
		"nohup rm -rf /x":                jms.CommandClass_DANGEROUS,
	}
	for cmd, want := range calm {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}
