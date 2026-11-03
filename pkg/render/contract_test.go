package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-mcp-kit/model/jms"
)

// The schema is what a tool PROMISES and what the server checks its answer
// against. A schema that is subtly wrong is worse than no schema: it either
// rejects answers that were fine, or lets through answers that were not.

func TestSchemaDescribesTheFields(t *testing.T) {
	s := Schema[Diagnosis]()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	props, _ := got["properties"].(map[string]any)
	for _, want := range []string{"checks", "findings", "status", "verdict", "advice"} {
		if _, ok := props[want]; !ok {
			t.Errorf("the schema has no %q property: %s", want, b)
		}
	}
	// The counting fields of a list are required, always: a caller must not
	// have to guess whether "total" is there.
	required, _ := got["required"].([]any)
	have := map[string]bool{}
	for _, r := range required {
		have[r.(string)] = true
	}
	for _, want := range []string{"checks", "findings", "status"} {
		if !have[want] {
			t.Errorf("%q is not required in the schema: %s", want, b)
		}
	}
}

func TestSchemaDescribesTheStatusAsItsWord(t *testing.T) {
	// The generated enum is an int64 with a name, but the contract says the
	// status of a check is the word "ok" / "warn" / "fail". Without the
	// override the schema would say "integer" while the answer says "ok",
	// and every diagnosis tool would fail its own contract.
	s := Schema[Diagnosis]()
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), `"type":"integer"`) {
		t.Errorf("the status is described as an integer: %s", b)
	}
	if !strings.Contains(string(b), `"ok"`) {
		t.Errorf("the status does not name its words: %s", b)
	}
}

func TestSchemaAllowsExtraFields(t *testing.T) {
	// A tool often carries context beyond the shared vocabulary. Forbidding
	// it would turn the contract into a straitjacket.
	s := Schema[Diagnosis]()
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), `"additionalProperties":false`) {
		t.Errorf("the schema forbids extra fields: %s", b)
	}
}

func TestSchemaOfAListCarriesTheCountingFields(t *testing.T) {
	s := Schema[ListOf[map[string]any]]()
	b, _ := json.Marshal(s)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	props, _ := got["properties"].(map[string]any)
	for _, want := range []string{"count", "total", "truncated", "items", "note"} {
		if _, ok := props[want]; !ok {
			t.Errorf("the list schema has no %q property: %s", want, b)
		}
	}
	required, _ := got["required"].([]any)
	have := map[string]bool{}
	for _, r := range required {
		have[r.(string)] = true
	}
	for _, want := range []string{"count", "total", "truncated"} {
		if !have[want] {
			t.Errorf("%q is not required: a caller would have to guess whether it is there", want)
		}
	}
}

func TestListOfNamesTheRowShape(t *testing.T) {
	// The whole point of ListOf: the row type is part of the contract.
	type row struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	s := Schema[ListOf[row]]()
	b, _ := json.Marshal(s)
	if !strings.Contains(string(b), `"items"`) {
		t.Fatalf("no items in the schema: %s", b)
	}
	if !strings.Contains(string(b), `"name"`) {
		t.Errorf("the row shape is not in the schema: %s", b)
	}
}

// The envelope must serialize the way the contract says: the counting fields
// at the top level, not nested under a meta object.
func TestListSerializesFlat(t *testing.T) {
	l := ListOf[map[string]any]{}
	l.Count = 3
	l.Total = 10
	l.Truncated = true
	l.Items = []map[string]any{{"id": "a"}}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	for _, want := range []string{"count", "total", "truncated", "items"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%q is not at the top level: %s", want, b)
		}
	}
	if _, ok := got["ListMeta"]; ok {
		t.Errorf("the counting fields are nested: %s", b)
	}
}

func TestDiagnosisSerializesItsWord(t *testing.T) {
	d := Diagnosis{Diagnosis: jms.Diagnosis{
		Checks:   []*jms.Check{{Name: "a", Status: jms.Status_ok, Detail: "fine"}},
		Findings: []*jms.Check{},
		Status:   jms.Status_ok,
	}}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"status":"ok"`) {
		t.Errorf("the status did not serialize as its word: %s", b)
	}
}
