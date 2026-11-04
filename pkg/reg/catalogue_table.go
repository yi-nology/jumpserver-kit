package reg

import (
	"io"

	"github.com/oekit/pkg/cli"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// CatalogueTable renders the audit view of the tool catalogue: one row per
// tool -- name, risk, and what it asks for. It is what the `tools`
// subcommand prints.
//
// hint fills in the rule of a CONDITIONAL confirmation, which carries no
// refusal sentence of its own. The lookup is the caller's: the policy
// table is each service's own risk side (pkg/ cannot depend on a service),
// and a hint function keeps the "the rule is still worth showing"
// decision in ONE place instead of one copy per service.
func CatalogueTable(w io.Writer, specs []jms.ToolSpec, hint func(name string) string) {
	tbl := cli.NewTable()
	for _, spec := range specs {
		confirm := ""
		if spec.Confirm != nil {
			confirm = *spec.Confirm
		} else if hint != nil {
			confirm = hint(spec.Name)
		}
		tbl.Append(spec.Name, spec.Risk.String(), confirm)
	}
	tbl.Render(w)
}
