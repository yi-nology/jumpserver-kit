package reg

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// CatalogueTable is the audit view of the tool directory: one row per tool
// with name, risk, and what it asks for. A CONDITIONAL confirmation carries
// no sentence of its own — the hint callback fills that column in, and only
// for tools that carry no confirmation of their own.
func TestCatalogueTableShowsNameRiskAndWhatItAsksFor(t *testing.T) {
	confirm := "set confirm=true to run"
	specs := []jms.ToolSpec{
		{Name: "jms_plain", Risk: jms.Risk_read},
		{Name: "jms_confirmed", Risk: jms.Risk_write, Confirm: &confirm},
		{Name: "jms_hinted", Risk: jms.Risk_write},
	}
	var buf bytes.Buffer
	CatalogueTable(&buf, specs, func(name string) string { return "RULE-" + name })
	out := buf.String()
	for _, want := range []string{
		"jms_plain", "jms_confirmed", "jms_hinted",
		specs[0].Risk.String(), specs[1].Risk.String(),
		confirm, "RULE-jms_hinted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("目录表格里没有 %q：\n%s", want, out)
		}
	}
	// The confirmation the tool carries wins: the hint is only the
	// fallback for tools with no sentence of their own.
	if strings.Contains(out, "RULE-jms_confirmed") {
		t.Errorf("带确认语的工具又盖了 hint 章：\n%s", out)
	}
}
