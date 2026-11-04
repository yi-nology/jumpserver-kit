package render_test

import (
	"reflect"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
)

// The schema must say the WORDS, and exactly the words the vocabulary
// documents: "ok" / "warn" / "fail" for a check's status, "READ" /
// "MODIFY" / "DANGEROUS" / "UNKNOWN" for a command class, and so on.
// Those words are what the agent reads and what the skills document — a
// schema that said "integer" here would fail every tool that answers in
// them, and a schema that spelled a word differently would send the agent
// looking for a value that does not exist.
func TestTheEnumPinsNameTheDocumentedWords(t *testing.T) {
	type wireEnums struct {
		Status   jms.Status       `json:"s"`
		Class    jms.CommandClass `json:"c"`
		Risk     jms.Risk         `json:"r"`
		Delivery jms.Delivery     `json:"d"`
	}
	s := render.Schema[wireEnums]()
	want := map[string][]string{
		"s": {"ok", "warn", "fail"},
		"c": {"READ", "MODIFY", "DANGEROUS", "UNKNOWN"},
		"r": {"read", "write", "destructive"},
		"d": {"not_sent", "maybe_sent"},
	}
	for field, names := range want {
		p := s.Properties[field]
		if p == nil {
			t.Errorf("field %q has no schema", field)
			continue
		}
		if p.Type != "string" {
			t.Errorf("field %q: type = %q, want string (the answer carries the word, not the number behind it)", field, p.Type)
		}
		got := enumNames(p)
		if !reflect.DeepEqual(got, names) {
			t.Errorf("field %q: enum = %v, want %v", field, got, names)
		}
	}
}

func enumNames(s *jsonschema.Schema) []string {
	out := make([]string, 0, len(s.Enum))
	for _, v := range s.Enum {
		name, _ := v.(string)
		out = append(out, name)
	}
	return out
}
