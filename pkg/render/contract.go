package render

// The output contract: what a tool promises, and the schema the server
// checks that promise against.
//
// The vocabulary behind these shapes lives in the IDL (model/jms for the
// shared words, and each server's own IDL for its domain shapes). What lives
// here is the ENVELOPE — the part every tool of a kind answers with — and the
// machinery that turns a Go type into a schema the SDK can validate against.
//
// The point of the envelope is that a caller learns it once. Every tool that
// answers "here are some of them" answers in the same shape, with the same
// three counting fields, so the agent does not have to learn a new layout per
// tool — and so a tool that quietly stops reporting "how many matched" fails
// loudly instead of answering a slightly different question each time.

import (
	"fmt"
	"github.com/oekit/pkg/slicex"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// ListOf is the answer to a query about many things, whose rows have a shape
// the server knows.
//
// It is the envelope every list answers in: the difference between it and a
// typed envelope with free-form rows is that the row type is part of the
// contract, so the schema says what each row looks like and the server
// checks it. A tool that returns a row without its promised field fails at
// the call instead of handing the caller a hole to trip over.
//
// There is deliberately no free-row variant any more (it was `render.List`,
// a list of `map[string]any`): a row whose field names are spelled by hand
// cannot be checked against the contract, so a row that lost a field was
// invisible. The row type is part of the answer now.
type ListOf[T any] struct {
	jms.ListMeta
	Items []T    `json:"items"`
	Note  string `json:"note,omitempty"`
}

// Diagnosis is the answer to a question about the state of something.
//
// It is jms.Diagnosis — the same five fields the diagnostic tools have always
// returned: the checks, the subset that needs attention, the overall
// grading, and the two sentences that say what it means and what to do.
type Diagnosis struct {
	jms.Diagnosis
}

// Schema returns the JSON Schema of a tool's declared output.
//
// The schema is what the tool PROMISES: the fields of the type are required
// (except the ones marked omitempty) and their types are checked, so a tool
// that stops returning a field fails at the call instead of quietly answering
// a different question.
//
// Extra fields are allowed on purpose. A tool often carries context beyond
// the shared vocabulary — the name of the asset a list is about, the note
// explaining a refusal — and forbidding them would turn the contract into a
// straitjacket instead of a promise.
//
// A schema that cannot be derived is a programming error, not a runtime
// condition: the tool is registered once, at start-up, and a tool that cannot
// describe its own output should not be running at all.
func Schema[T any]() *jsonschema.Schema {
	s, err := jsonschema.For[T](&jsonschema.ForOptions{TypeSchemas: typeSchemas})
	if err != nil {
		panic(fmt.Sprintf("jms: cannot describe the output of type %T: %v", *new(T), err))
	}
	relax(s)
	return s
}

// typeSchemas pins the JSON of the types whose wire form is not their Go
// form.
//
// The generated enums are an int64 with a name, but the contract says the
// status of a check is the word "ok" / "warn" / "fail" — that string is what
// the agent reads and what the skills document. Without this the schema would
// say "integer" while the answer says "ok", and every diagnosis tool would
// fail its own contract.
var typeSchemas = map[reflect.Type]*jsonschema.Schema{
	reflect.TypeFor[jms.Status](): {
		Type: "string",
		Enum: []any{"ok", "warn", "fail"},
	},
}

// relax allows additional properties on every object in the schema.
//
// The check is for "this schema describes an object", not for a particular
// spelling of that: a nullable object carries its type as a list
// ("null", "object"), and a map carries none at all.
func relax(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	if isObject(s) {
		// A struct's schema says "no extra fields" by default, and a tool
		// often carries context beyond the shared vocabulary — the name of
		// the asset a list is about, the note explaining a refusal — so
		// extras are allowed on purpose.
		//
		// A map's schema is the other thing entirely: there,
		// additionalProperties IS the schema of the values, and overwriting
		// it would throw the check on every value away. The two are told
		// apart by whether the schema has properties of its own.
		if len(s.Properties) > 0 || s.AdditionalProperties == nil {
			s.AdditionalProperties = &jsonschema.Schema{}
		}
	}
	for _, p := range s.Properties {
		relax(p)
	}
	relax(s.Items)
	relax(s.AdditionalProperties)
	for _, p := range s.PrefixItems {
		relax(p)
	}
	for _, p := range s.AllOf {
		relax(p)
	}
	for _, p := range s.AnyOf {
		relax(p)
	}
	for _, p := range s.OneOf {
		relax(p)
	}
	for _, p := range s.Defs {
		relax(p)
	}
}

// isObject reports whether a schema describes an object.
func isObject(s *jsonschema.Schema) bool {
	if s.Type == "object" {
		return true
	}
	if slicex.Contains(s.Types, "object") {
		return true
	}
	return len(s.Properties) > 0
}
