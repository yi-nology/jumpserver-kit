// Package httpapi serves the tool registry over HTTP, twice:
//
//   - MCP over streamable HTTP, for agent runtimes that speak MCP over a
//     socket instead of stdio;
//   - a small REST surface, for humans, scripts and anything that just
//     wants to call a tool.
//
// ⚠️ Both faces go through the SAME registry (pkg/reg) ⇒ the same risk
// gate, the same confirm semantics and the same audit trail. The REST
// face is not a back door: a call refused on stdio is refused here, and
// every call leaves one line, whatever face it came in on.
//
// ⚠️ Everything except /api/v1/health requires the bearer token. Health
// is open because a liveness probe cannot hold a secret; it reports
// nothing the process does not say by existing (name, version, tool
// count).
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
)

// RestCaller is the audit trail's self-reported client name for calls that
// come in over the REST face.
//
// ⚠️ It is deliberately one word: the REST face authenticates a token, not
// a person, and the trail must not read "alice" when all it knows is
// "the holder of the HTTP token". The remote address is not in the trail
// either — the trail's client column holds a name, not a location.
const RestCaller = "rest"

// maxBody caps a REST invoke body. Tool arguments are small (ids, names,
// a command line); a body larger than this is a mistake or an attack.
const maxBody = 1 << 20 // 1 MiB

// Options is what the HTTP surface needs to know beyond the registry.
type Options struct {
	// Token is the bearer token every protected route demands.
	//
	// ⚠️ There is no "auth off" mode: a service that answers tool calls
	// answers them to whoever can reach the port, and "whoever can reach
	// the port" is not an access policy.
	Token string
	// Name and Version identify the server (health, OpenAPI document).
	Name    string
	Version string
	// ReadOnly is reported by health so a caller can tell what kind of
	// server it reached before it tries a write.
	ReadOnly bool
}

// Server is the HTTP surface of one registry.
type Server struct {
	reg  *reg.Registry
	opts Options
	mcp  *mcp.StreamableHTTPHandler
	mux  *http.ServeMux
}

// New builds the HTTP surface. It fails when no token is configured: a
// surface with no way to say no is not a surface this package will
// hand out.
func New(r *reg.Registry, opts Options) (*Server, error) {
	if opts.Token == "" {
		return nil, errors.New("httpapi: no bearer token configured — refusing to serve without one")
	}
	s := &Server{
		reg:  r,
		opts: opts,
		// The SDK's defaults protect a local server against DNS rebinding;
		// nothing here serves across hosts.
		mcp: r.StreamableHTTPHandler(nil),
		mux: http.NewServeMux(),
	}
	// AllowMissingExpiration: the configured token is a deployment
	// secret, not an IdP token — its lifetime is whatever the operator
	// makes of it (rotate the env value), not an in-band exp claim. The
	// option exists for exactly this shape of token.
	authed := auth.RequireBearerToken(s.verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})
	s.mux.HandleFunc("GET /api/v1/health", s.health)
	s.mux.Handle("GET /api/v1/tools", authed(http.HandlerFunc(s.tools)))
	s.mux.Handle("POST /api/v1/tools/{name}/invoke", authed(http.HandlerFunc(s.invoke)))
	// The MCP endpoint takes GET (the event stream), POST (messages) and
	// DELETE (session end); the handler knows the protocol, the mux only
	// routes.
	s.mux.Handle("/mcp", authed(s.mcp))
	return s, nil
}

// Handler returns the routed surface.
func (s *Server) Handler() http.Handler { return s.mux }

// verify checks one bearer token against the configured one.
//
// The comparison is constant-time: the token is the whole access policy,
// and an oracle that says "the first four bytes were right" is a leak.
func (s *Server) verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	want := []byte(s.opts.Token)
	got := []byte(token)
	if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{UserID: RestCaller}, nil
}

// health answers a liveness probe. It is the one open route: a probe
// cannot hold a secret, and the answer says nothing sensitive.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"server":    s.opts.Name,
		"version":   s.opts.Version,
		"read_only": s.opts.ReadOnly,
		"tools":     len(s.reg.Specs()),
	})
}

// tools answers the catalogue: every tool with its risk, its confirmation
// rule and its declared shapes.
//
// The rows are assembled by the registry (reg.Catalogue) — it is the one
// place that holds a tool's spec and its schemas together. This face only
// serialises them.
func (s *Server) tools(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tools": s.reg.Catalogue()})
}

// InvokeResult is the REST face's answer to one tool call.
//
// ⚠️ A refused or failed call is still HTTP 200: the call happened, and
// its OUTCOME was a refusal or a failure. HTTP status describes the
// request, is_error describes the call — collapsing them would turn
// "the gate stopped you" into "your request was malformed", which is
// the wrong sentence.
type InvokeResult struct {
	Tool    string `json:"tool"`
	IsError bool   `json:"is_error"`
	Text    string `json:"text"`
	// Structured is the tool's structured answer when it declared one.
	Structured any `json:"structured,omitempty"`
}

// invoke calls one tool. The body IS the tool's arguments — the same JSON
// an MCP client would put in params.arguments.
func (s *Server) invoke(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.reg.Has(name) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such tool: " + name})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot read body: " + err.Error()})
		return
	}
	if len(body) > maxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		body = []byte("{}")
	}
	if !json.Valid(body) || body[0] != '{' {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "body must be a JSON object: the tool's arguments"})
		return
	}
	// The same door as stdio: the gate, the confirm rule and the trail all
	// live below this line (see pkg/reg).
	res, err := s.reg.CallTool(r.Context(), RestCaller, name, json.RawMessage(body))
	if err != nil {
		// ⚠️ NOT a bad argument: arguments that do not fit the tool's
		// schema come back as an ANSWER (200 + is_error), exactly like
		// stdio (TestArgumentsThatDoNotFitAreAnAnswerToo). When we are
		// here the call could not even be delivered to the server
		// (session/transport failure) ⇒ the fault is ours ⇒ 500. Saying
		// 400 would tell the caller "your request is malformed" about a
		// failure inside this process — the wrong sentence.
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, InvokeResult{
		Tool:       name,
		IsError:    res.IsError,
		Text:       render.ResultText(res),
		Structured: res.StructuredContent,
	})
}

// The result's text is read with the one definition the repository has
// for it: render.ResultText (a tool answers in one JSON block, but the
// envelope carries the text as text — a caller that wants the structure
// reads `structured`).

// writeJSON writes one JSON answer.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// The status line is already out; there is nothing left to change.
	// Encode only fails on an unencodable value or a dead connection, and
	// this package marshals its own answers.
	_ = json.NewEncoder(w).Encode(v)
}
