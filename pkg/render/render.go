// Package render shapes what a tool hands back to the caller.
//
// Every tool answers in the same envelope: one JSON block for success, one
// "ERROR: ..." line for failure. The shape lives here so that the 76 tools
// do not each grow their own idea of what a result looks like.
//
// The error text keeps its historic prefix. A model (and an operator
// reading a transcript) has learned to look for "ERROR:" — that prefix is
// part of the contract, not decoration.
package render

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Text renders a value as the tool's result.
//
// The value is handed back as the tool's STRUCTURED output, not as pre-rendered
// text. That is what makes the output a contract rather than a convention:
//
//   - the server checks the value against the tool's declared output schema
//     before the model ever sees it, so a tool that quietly stops returning a
//     field fails loudly instead of returning a different shape;
//   - the model receives it as structuredContent — data it can read as data —
//     and the JSON text stays as the fallback for clients that only read text.
//
// The shape of the value is therefore a promise the server keeps. Which shape
// a particular tool promises lives in its output schema; the shared
// vocabulary behind those shapes lives in the IDL (model/jms).
func Text(v any) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{}, v, nil
}

// Err renders an error as a failed tool result.
func Err(err error) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: " + err.Error()}},
	}, nil, nil
}

// Failf renders a formatted error as a failed tool result.
//
// It exists so a tool body can build a message with arguments without
// nesting fmt.Errorf inside Err.
func Failf(format string, a ...any) (*mcp.CallToolResult, any, error) {
	return Err(fmt.Errorf(format, a...))
}
