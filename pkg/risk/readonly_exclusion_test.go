package risk

import (
	"testing"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// 含 I/O 或执行原语的 mini-language 不能进只读表（tools#81 + 下游同族排查）。
// sed 的 w/W/e 与 awk 的 system()/管道执行都是写或执行路径——「listed =
// proven read-only」的契约对它们不成立。除名后必须落进非 READ 档：
// READ 是「解析器证明它不能写」的最强承诺，对这两族给不出。
func TestMiniLanguagesAreNeverReadOnly(t *testing.T) {
	cases := []string{
		"sed -n 'w /tmp/exfil' /etc/hosts",
		"echo x | sed 's/a/b/w /tmp/out'",
		"sed 's/x/y/e' /etc/hosts",
		"sed -e '1w /tmp/one' -e 's/a/b/' /etc/hosts",
		"awk 'BEGIN{system(\"touch /tmp/pwned\")}' /etc/hosts",
		"awk '/x/{print | \"sh -c id > /tmp/p\"}' /etc/hosts",
	}
	for _, cmd := range cases {
		if class := Classify(cmd); class == jms.CommandClass_READ {
			t.Errorf("%q classified READ — the exclusion did not take: sed/awk carry I/O and exec primitives", cmd)
		}
	}
}

// 除名的代价要被钉住：日常形态（纯文本过滤）不再享受 READ 档——这是
// 故意的（诚实标注优先于免检便利），落进 MODIFY、照旧免确认。
func TestDemotedMiniLanguagesFallToModifyWithoutNewFriction(t *testing.T) {
	for _, cmd := range []string{
		"sed -n 's/a/b/' /etc/hosts",
		"df -h | awk '{print $1}'",
	} {
		if class := Classify(cmd); class != jms.CommandClass_MODIFY {
			t.Errorf("%q = %s, want MODIFY (demoted, honestly labelled, still confirm-free)",
				cmd, class.String())
		}
	}
}
