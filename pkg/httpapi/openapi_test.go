package httpapi

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

func TestOpenAPIIsByteStable(t *testing.T) {
	records := []reg.Record{}
	_, r := testServer(t, &records)
	opts := Options{Token: "sekrit", Name: "httpapi-test", Version: "1"}

	one, err := OpenAPI(r, opts)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	two, err := OpenAPI(r, opts)
	if err != nil {
		t.Fatalf("render again: %v", err)
	}
	if !bytes.Equal(one, two) {
		t.Fatal("two renders of the same catalogue differ — the checked-in copy could never be diffed against a regeneration")
	}
}

func TestOpenAPIDescribesTheSurfaceAndEveryTool(t *testing.T) {
	records := []reg.Record{}
	_, r := testServer(t, &records)
	b, err := OpenAPI(r, Options{Name: "httpapi-test", Version: "1"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc struct {
		Paths      map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("the document is not JSON: %v", err)
	}
	for _, want := range []string{
		"/api/v1/health",
		"/api/v1/tools",
		"/mcp",
		"/api/v1/tools/echo/invoke",
		"/api/v1/tools/danger/invoke",
	} {
		if _, ok := doc.Paths[want]; !ok {
			t.Errorf("the document has no %s", want)
		}
	}
	for _, want := range []string{"InvokeResult", "Error", "ToolInput_echo", "ToolOutput_echo", "ToolResult_echo"} {
		if _, ok := doc.Components.Schemas[want]; !ok {
			t.Errorf("the document has no schema %s", want)
		}
	}
	// The input shape in the document is the tool's own argument shape —
	// that is the "same source" promise the swagger/ layer rests on.
	input := string(doc.Components.Schemas["ToolInput_echo"])
	if !json.Valid(doc.Components.Schemas["ToolInput_echo"]) || !contains(input, "message") {
		t.Fatalf("ToolInput_echo must carry the tool's argument shape, got %s", input)
	}
}

// contains is strings.Contains without the import dance in this file.
func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
