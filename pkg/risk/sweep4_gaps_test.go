package risk

import (
	"testing"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// #28:kubectl 的「创建并进去执行」三兄弟(exec / run / debug)同破坏面——
// 载荷跑在 pod、临时容器或 node 宿主里,从来没进过本机进程,必须按
// peelElsewhere 同一条纪律重判。run 与 debug 的内层只在 -- 之后(run 的
// NAME 是要创建的 pod 名,debug 的 TARGET 是被调试对象,都不是命令);
// 无 -- = 没有可判的内层,按原样走 destructive()。
func TestKubectlPayloadSubcommandsAreJudged(t *testing.T) {
	dangerous := []string{
		"kubectl run tmp --rm -it --restart=Never --image=busybox -- rm -rf /data",
		"kubectl run tmp --image=busybox -- rm -rf /data",
		"kubectl -n prod run tmp --image=busybox -- rm -rf /data", // 全局旗标前置
		"kubectl debug node/mynode -it --image=busybox -- rm -rf /data",
		"kubectl debug pod/web --image=busybox -- rm -rf /data",
		"kubectl exec pod-1 -- rm -rf /data", // #26 既有判定不丢
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS — the payload runs elsewhere and must be re-judged", cmd, got)
		}
	}

	// 对照组:载荷可逆 / 无载荷的形态不升级。
	calm := map[string]jms.CommandClass{
		"kubectl run tmp --image=busybox -- echo hi":               jms.CommandClass_MODIFY,
		"kubectl run --rm -it --restart=Never --image=busybox tmp": jms.CommandClass_MODIFY, // 无 -- = 无载荷
		"kubectl debug node/mynode --image=busybox -it":            jms.CommandClass_MODIFY, // 无载荷(起交互 shell)
		"kubectl run tmp --restart=Never --image=busybox":          jms.CommandClass_MODIFY,
		"kubectl exec pod-1 -- ls /data":                           jms.CommandClass_MODIFY, // #26 对照不回归
		"kubectl cp pod-1:/etc/passwd ./passwd":                    jms.CommandClass_MODIFY, // 方向性拷贝,工具策略层的事
		"kubectl delete pod web-1":                                 jms.CommandClass_DANGEROUS,
		"kubectl apply --prune -f manifests/ --dry-run=client":     jms.CommandClass_MODIFY, // dry run 什么都不删
	}
	for cmd, want := range calm {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}

// #31:destructive 的 kubectl 分支原来只认 delete 与 --dry-run 放行——
// --prune 把 apply 变成 delete(清单之外的现存资源被删除,删除路径不可逆),
// drain 的 --delete-emptydir-data(emptyDir 随驱逐清空)与 --force(删不受
// 控制器管理的 pod)带着删数据语义。裸 drain 只是驱逐(可恢复),维持原判定。
func TestKubectlPruneAndDrainCarryTheDeleteBlastRadius(t *testing.T) {
	dangerous := []string{
		"kubectl apply --prune -f manifests/",
		"kubectl apply -f manifests/ --prune=true", // 等号拼写载有 --prune
		"kubectl drain node1 --ignore-daemonsets --delete-emptydir-data --force",
		"kubectl drain node1 --force",
		"kubectl drain node1 --delete-emptydir-data",
		"kubectl delete pod web-1", // 既有判定不丢
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS — the deletion path must ask for confirmation", cmd, got)
		}
	}

	calm := map[string]jms.CommandClass{
		"kubectl apply -f deploy.yaml":                 jms.CommandClass_MODIFY, // 既有锚点
		"kubectl drain node1":                          jms.CommandClass_MODIFY, // 裸驱逐可恢复
		"kubectl drain node1 --ignore-daemonsets":      jms.CommandClass_MODIFY,
		"kubectl cordon node1":                         jms.CommandClass_MODIFY,
		"kubectl uncordon node1":                       jms.CommandClass_MODIFY,
		"kubectl apply --prune -f m/ --dry-run=client": jms.CommandClass_MODIFY, // dry run 什么都不删
	}
	for cmd, want := range calm {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}

// #30:helm 此前无条目——delete/uninstall(删整个 release,含其全部对象)
// 与 kubectl delete 同破坏面却落兜底 MODIFY 免确认;只读形态也拿不到 READ 档。
// uninstall 的别名族(del / delete / un,helm 的 cobra Aliases)必须同档
// ——换拼写换档就是 kit#23 那条稳定的免确认旁路。rollback 可逆,维持原判定。
func TestHelmReleaseDeletionRequiresConfirmation(t *testing.T) {
	dangerous := []string{
		"helm delete web",
		"helm uninstall web",
		"helm del web",
		"helm un web",
		"sudo helm delete web", // 剥壳叠加
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS — deleting a release deletes every object it owns", cmd, got)
		}
	}

	calm := map[string]jms.CommandClass{
		"helm rollback web 1":      jms.CommandClass_MODIFY, // 可逆
		"helm upgrade web ./chart": jms.CommandClass_MODIFY,
		"helm install web ./chart": jms.CommandClass_MODIFY, // 可逆(uninstall-able)
	}
	for cmd, want := range calm {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}

// #32:设备写入的三条语法通道(dd、重定向、tee)必须同一个门——dd 的 of=
// 在表里,重定向有 dangerousRedirect,tee 此前免确认。tee 的目标操作数落在
// /dev/* 设备节点 ⇒ 与 dd of=/dev/sda 同破坏面;/dev/null 与 /dev/zero 丢弃
// 写入,与 dangerousRedirect 同一豁免;普通文件目标与重定向同档,不升级。
func TestTeeDeviceTargetIsTheThirdWriteChannel(t *testing.T) {
	dangerous := []string{
		"echo x | tee /dev/sda",
		"echo x | tee -a /dev/sda", // 追加形态同逃
		"tee /dev/sda",
		"echo x | tee /dev/vdb",
		"tee --output-error=exit /dev/sda",
		"dd of=/dev/sda",          // 既有判定不丢
		"cat disk.img > /dev/sda", // 既有判定不丢(重定向通道)
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS — writing a device node is irreversible", cmd, got)
		}
	}

	calm := map[string]jms.CommandClass{
		"echo x | tee /etc/hosts":      jms.CommandClass_MODIFY, // 普通文件目标,与重定向同档
		"echo x | tee /dev/null":       jms.CommandClass_MODIFY, // 丢弃写入
		"echo x | tee -a /tmp/app.log": jms.CommandClass_MODIFY,
	}
	for cmd, want := range calm {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}

// #33:truncate 对任意文件本就是数据销毁原语(不可逆截断),journalctl
// --vacuum(已 DANGEROUS)的同意图旁路。按方案 A 全量入档(与 shred 同族
// 对齐)——路径清单收窄(方案 B)换个路径照样销毁任意数据,精准是假的。
func TestTruncateIsTheJournalctlVacuumBypass(t *testing.T) {
	dangerous := []string{
		"truncate -s 0 /var/log/secure", // 清审计日志,与 --vacuum 同意图
		"truncate --size 0 /var/log/wtmp",
		"truncate -s 0 /tmp/big.dat",  // 合法瘦身场景也要确认——误报=一次确认
		"journalctl --vacuum-size=1G", // 同意图锚点,既有判定不丢
		"shred /tmp/secret",           // 同族锚点(shred 恒 DANGEROUS)
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS — irreversible truncation", cmd, got)
		}
	}
}

// #34:crontab 是「怎么进来的机制」家族的调度入口——-r 删整张表(不可逆,
// 原调度内容丢失);文件 / stdin(含裸调用读 stdin)安装是持久化原语,
// 与 useradd/passwd 同族。三种形态三种档:-l 只读,-e 交互态维持,-r 与
// 安装形态要确认。
func TestCrontabInstallAndWipeRequireConfirmation(t *testing.T) {
	dangerous := []string{
		"crontab -r", // 删整表,不可逆
		"crontab -u bob -r",
		"echo x | crontab -",   // stdin 安装
		"echo x | crontab",     // 裸调用读 stdin = 安装形态
		"crontab /tmp/newcron", // 文件安装
		"crontab -u bob /tmp/newcron",
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS — scheduling is a persistence primitive", cmd, got)
		}
	}

	calm := map[string]jms.CommandClass{
		"crontab -e": jms.CommandClass_MODIFY, // 交互态,exec 通道跑不通,维持
	}
	for cmd, want := range calm {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}

// #35:ip 族整体缺席——flush 家族清空路由/地址/邻居表(远程机器直接失联),
// link set down 拔网线,link del 删接口。对经堡垒机远程操作的执行面,断网类
// 操作还把操作者自己锁在外面。与 iptables -F 同破坏面,同一档。
func TestIPFamilyNetworkCutsRequireConfirmation(t *testing.T) {
	dangerous := []string{
		"ip route flush table main",
		"ip -6 route flush", // IPv6 同逃
		"ip addr flush dev eth0",
		"ip neigh flush all",
		"ip link set eth0 down",
		"ip link set dev eth0 down",
		"ip link del eth0.100",
		"ip link delete veth0",
		"sudo ip link set eth0 down", // 剥壳叠加
	}
	for _, cmd := range dangerous {
		if got := Classify(cmd); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS — cutting the network locks the operator out", cmd, got)
		}
	}

	calm := map[string]jms.CommandClass{
		"ip link set eth0 up":              jms.CommandClass_MODIFY, // 拉起接口不升级
		"ip addr add 10.0.0.5/24 dev eth0": jms.CommandClass_MODIFY, // 加地址可逆
		"ip route del default":             jms.CommandClass_MODIFY, // 单条删除可重加,issue 未要求
	}
	for cmd, want := range calm {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}

// #29/#30/#34/#35 的只读侧:config 收窄到真只读形态(use-context 写
// kubeconfig,不能顶着 READ 档)、kubectl/helm/crontab/ip 的日常巡检形态
// 拿回 READ 档标签(纯标签精度,不改门禁行为——MODIFY 与 READ 都免确认)。
func TestReadOnlyLabelsForSweepForms(t *testing.T) {
	read := []string{
		// #29:config 收窄——剩下的都是查形态。
		"kubectl config view",
		"kubectl config current-context",
		"kubectl config get-contexts",
		// #29:旗标精度——全局旗标(子命令前)与子命令旗标(子命令后)都要认。
		"kubectl get pods",
		"kubectl get pods -A",
		"kubectl get pods -o wide",
		"kubectl -n prod get pods",
		"kubectl get pods -n prod",
		"kubectl logs pod-1 -f --tail 100",
		"kubectl top pods -A",
		"kubectl version -o json",
		// #30:helm 只读形态。
		"helm list",
		"helm list -A",
		"helm status web",
		"helm history web",
		"helm get values web",
		"helm env",
		"helm show chart nginx",
		"helm template web ./chart",
		// #34:crontab -l 只读(带 -u 限定照旧)。
		"crontab -l",
		"crontab -u bob -l",
		// #35:ip 只读形态。
		"ip addr show",
		"ip -6 addr show",
		"ip -br addr",
		"ip route list",
		"ip route show dev eth0",
		"ip route get 10.0.0.1",
		"ip route",
		"ip link",
	}
	for _, cmd := range read {
		if got := Classify(cmd); got != jms.CommandClass_READ {
			t.Errorf("Classify(%q) = %s, want READ", cmd, got)
		}
	}

	// 标签收回/维持的对照:这些形态不是只读。
	notRead := map[string]jms.CommandClass{
		"kubectl config use-context prod":                   jms.CommandClass_MODIFY, // 写 kubeconfig,从 READ 收回(#29)
		"kubectl config set-context x --cluster=c --user=u": jms.CommandClass_MODIFY,
		"kubectl auth reconcile -f rbac.yaml":               jms.CommandClass_MODIFY, // 写动词,-f 不在安全表
		"crontab -e":                                        jms.CommandClass_MODIFY, // 交互态,不进只读表
		"crontab -r":                                        jms.CommandClass_DANGEROUS,
		"helm delete web":                                   jms.CommandClass_DANGEROUS, // 写动词留在表外,由 destructive 判
		"ip link set eth0 down":                             jms.CommandClass_DANGEROUS,
		"ip route flush":                                    jms.CommandClass_DANGEROUS,
		"kubectl delete pod web-1":                          jms.CommandClass_DANGEROUS, // 既有判定不丢
		"journalctl -u nginx --since '1 hour ago'":          jms.CommandClass_READ,      // 既有只读不回归
	}
	for cmd, want := range notRead {
		if got := Classify(cmd); got != want {
			t.Errorf("Classify(%q) = %s, want %s", cmd, got, want)
		}
	}
}
