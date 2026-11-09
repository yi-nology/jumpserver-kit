package risk

import (
	"testing"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// 含 I/O 或执行原语的 mini-language 不能进只读表（tools#81 + 下游同族排查）。
// sed 的 w/W/e 与 awk 的 system()/管道执行都是写或执行路径——「listed =
// proven read-only」的契约对它们不成立。除名之后还有后半段：落 MODIFY
// 照旧免确认，所以脚本内容带写/执行原语的调用必须在深检里判 DANGEROUS
//（要确认）——RCE 形态不能与纯文本过滤走同一条免确认车道。
func TestMiniLanguageExecPrimitivesRequireConfirmation(t *testing.T) {
	cases := []string{
		"sed -n 'w /tmp/exfil' /etc/hosts",
		"echo x | sed 's/a/b/w /tmp/out'",
		"sed 's/x/y/e' /etc/hosts",
		"sed -e '1w /tmp/one' -e 's/a/b/' /etc/hosts",
		"sed '2,10W /tmp/ten' /var/log/audit.log",
		"sed -f payload.sed /etc/hosts",
		"awk 'BEGIN{system(\"touch /tmp/pwned\")}' /etc/hosts",
		"awk '/x/{print | \"sh -c id > /tmp/p\"}' /etc/hosts",
		"awk '{print $1 > \"/tmp/leak\"}' /etc/hosts",
		"awk -f payload.awk /etc/hosts",
	}
	for _, cmd := range cases {
		if class := Classify(cmd); class != jms.CommandClass_DANGEROUS {
			t.Errorf("%q = %s, want DANGEROUS — the script carries I/O or exec primitives and must ask for confirmation",
				cmd, class.String())
		}
	}
}

// 除名的代价要被钉住：日常形态（纯文本过滤、数值比较）不升级也不降级
// ——落进 MODIFY、照旧免确认，深检对它们零新增摩擦。
func TestDemotedMiniLanguagesFallToModifyWithoutNewFriction(t *testing.T) {
	for _, cmd := range []string{
		"sed -n 's/a/b/' /etc/hosts",
		"df -h | awk '{print $1}'",
		"awk -F: '{print $1}' /etc/passwd",
		"awk '$3 > 100 {print}' /var/log/disk.log",
		"sed 's/eval/e/' /etc/hosts",
	} {
		if class := Classify(cmd); class != jms.CommandClass_MODIFY {
			t.Errorf("%q = %s, want MODIFY (benign filter: demoted, honestly labelled, still confirm-free)",
				cmd, class.String())
		}
	}
}
