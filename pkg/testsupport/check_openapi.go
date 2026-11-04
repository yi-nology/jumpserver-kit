package testsupport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/httpapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

// OpenAPICheck describes one service's OpenAPI guard: where the document
// lives, what version and face name to render under, and the registry
// assembly the SERVER serves (each service has its own).
type OpenAPICheck struct {
	// Root is the repository root: swagger/openapi.json lives under it.
	Root string
	// Version is the binary's Version constant -- the document's
	// info.version is compared against it.
	Version string
	// Name is the face name the document is rendered under.
	Name string
	// ToolMark is a byte sequence only a document WITH tools carries
	// ("/api/v1/tools/jms_" / "/api/v1/tools/jmsx_"): an empty registry
	// must not pass just because the regeneration renders the same
	// emptiness.
	ToolMark string
	// New assembles the registry the document is rendered from. It must
	// be the same code path the server serves -- a guard that builds its
	// own catalogue proves only that its own catalogue renders.
	New func() *reg.Registry
}

// CheckOpenAPI asserts that the checked-in swagger/openapi.json is the
// document rendered from the tool registry -- the same one the MCP face
// serves. So the contract a REST caller codes against and the tools an
// agent calls cannot drift apart: change a tool, regenerate, or this
// names the difference.
//
// ⚠️ The version is compared too, and that is the common failure: the
// Version constant is bumped for a release and the document is not
// regenerated ⇒ the shipped contract documents the PREVIOUS release. The
// regeneration is ./script/gen-openapi.sh; its output is checked in.
//
// It lives here because both services guard the same thing with the same
// words -- and two copies of a guard drift like two copies of anything.
func CheckOpenAPI(t *testing.T, c OpenAPICheck) {
	t.Helper()
	checkedIn, err := os.ReadFile(filepath.Join(c.Root, "swagger", "openapi.json"))
	if err != nil {
		t.Fatalf("swagger/openapi.json: %v — run ./script/gen-openapi.sh", err)
	}
	got, err := httpapi.OpenAPI(c.New(), httpapi.Options{Name: c.Name, Version: c.Version})
	if err != nil {
		t.Fatalf("render the document: %v", err)
	}
	if !bytes.Contains(got, []byte(c.ToolMark)) {
		t.Fatal("the generated document lists no tool at all: the registry " +
			"came up empty, and an empty document matching an empty document " +
			"is not a contract")
	}
	if bytes.Equal(checkedIn, got) {
		return
	}
	line, want, have := firstDiffLine(checkedIn, got)
	hint := ""
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	_ = json.Unmarshal(checkedIn, &doc)
	if doc.Info.Version != c.Version {
		hint = "\n文档的 info.version 是 " + doc.Info.Version + "，二进制的版本是 " +
			c.Version + " —— 抬了 Version 常量就得重新生成文档"
	}
	t.Errorf("swagger/openapi.json 与工具目录对不上（第 %d 行起）%s：\n"+
		"  签入的: %s\n  生成的: %s\n"+
		"改了工具、契约或版本就跑 ./script/gen-openapi.sh，把重新生成的 "+
		"swagger/openapi.json 一起提交", line, hint, want, have)
}

// firstDiffLine reports the first line where the two documents disagree.
func firstDiffLine(a, b []byte) (int, string, string) {
	al := strings.Split(string(a), "\n")
	bl := strings.Split(string(b), "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var av, bv string
		if i < len(al) {
			av = al[i]
		}
		if i < len(bl) {
			bv = bl[i]
		}
		if av != bv {
			return i + 1, av, bv
		}
	}
	return 0, "", ""
}
