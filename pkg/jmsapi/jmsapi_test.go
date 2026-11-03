package jmsapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/errs"
)

// The tests here are about the WIRE, not about meaning: the two list shapes,
// the labelled-choice fields, the empty 204, and the one behaviour that had
// already drifted between the two servers — truncating a multi-byte character.

func testClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(Options{
		BaseURL:           srv.URL,
		Token:             "t",
		Timeout:           10 * time.Second,
		RequestsPerSecond: 1000,
		Burst:             100,
	})
}

func TestTruncateKeepsMultiByteCharactersIntact(t *testing.T) {
	// The bug this guards: a byte slice cuts a multi-byte character in half
	// and the invalid bytes come out of the JSON result as replacement
	// characters. The execution plane carried a byte-slicing copy for a while.
	s := "错误：没有可用的授权账号或终端协议"
	got := Truncate(s, 5)
	if !isValidUTF8(got) {
		t.Fatalf("Truncate produced invalid UTF-8: %q", got)
	}
	if strings.ContainsRune(got, '�') {
		t.Fatalf("Truncate produced a replacement character: %q", got)
	}
	if len([]rune(got)) > 6 { // 5 runes plus the ellipsis
		t.Fatalf("Truncate kept too much: %q", got)
	}
	// A string that fits must come back untouched, not with an ellipsis.
	if got := Truncate("short", 100); got != "short" {
		t.Fatalf("Truncate changed a short string: %q", got)
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

func TestListUnpacksBothShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"bare array", `[{"id":"a"},{"id":"b"}]`, 2},
		{"envelope", `{"count":2,"results":[{"id":"a"},{"id":"b"}]}`, 2},
		{"empty envelope", `{"count":0,"results":[]}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := List(json.RawMessage(tc.body))
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(rows) != tc.want {
				t.Fatalf("List returned %d rows, want %d", len(rows), tc.want)
			}
		})
	}
}

func TestListRejectsAnUnknownShape(t *testing.T) {
	// An unknown shape must be an error, not an empty list: "no rows" and
	// "the response was not what we expected" are different claims, and only
	// one of them is true.
	if _, err := List(json.RawMessage(`{"detail":"nope"}`)); err == nil {
		t.Fatal("List accepted an unknown shape")
	}
}

func TestLabelAndFieldName(t *testing.T) {
	m := map[string]any{
		"connectivity": map[string]any{"value": "ok", "label": "OK"},
		"platform":     map[string]any{"id": "p1", "name": "Linux"},
		"bare":         "plain",
		"empty":        nil,
	}
	if got := Label(m, "connectivity"); got != "ok" {
		t.Errorf("Label of a labelled choice = %q, want ok", got)
	}
	if got := Label(m, "bare"); got != "plain" {
		t.Errorf("Label of a bare value = %q, want plain", got)
	}
	if got := Label(m, "empty"); got != "" {
		t.Errorf("Label of nil = %q, want empty", got)
	}
	if got := Label(m, "absent"); got != "" {
		t.Errorf("Label of a missing key = %q, want empty", got)
	}
	if got := FieldName(m, "platform"); got != "Linux" {
		t.Errorf("FieldName of a nested object = %q, want Linux", got)
	}
	if got := FieldName(m, "bare"); got != "plain" {
		t.Errorf("FieldName of a bare value = %q, want plain", got)
	}
}

func TestNestedStopsAtAMissingLink(t *testing.T) {
	m := map[string]any{"a": map[string]any{"b": map[string]any{"c": 1}}}
	if got := Nested(m, "a", "b", "c"); got != 1 {
		t.Errorf("Nested = %v, want 1", got)
	}
	if got := Nested(m, "a", "x", "c"); got != nil {
		t.Errorf("Nested through a missing link = %v, want nil", got)
	}
	if got := Nested(m, "a", "b", "c", "d"); got != nil {
		t.Errorf("Nested through a non-object = %v, want nil", got)
	}
}

func TestDoTreatsAnEmptyBodyAsSuccess(t *testing.T) {
	// Several v5 endpoints answer a successful write with 204 and no body.
	// Decoding that as JSON turns a write that worked into "unexpected end of
	// JSON input", which reads as a failure and makes the caller believe
	// nothing happened.
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	var out map[string]any
	if err := c.Do(context.Background(), "DELETE", "/assets/assets/x/", nil, nil, &out); err != nil {
		t.Fatalf("Do on an empty 204: %v", err)
	}
}

func TestDoClassifiesAnErrorStatus(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"forbidden"}`))
	}))
	err := c.Do(context.Background(), "GET", "/assets/assets/", nil, nil, nil)
	if err == nil {
		t.Fatal("Do accepted a 403")
	}
	var apiErr *errs.APIError
	if !asAPIError(err, &apiErr) {
		t.Fatalf("Do returned %T, want *errs.APIError", err)
	}
	if apiErr.Status != http.StatusForbidden {
		t.Errorf("APIError.Status = %d, want 403", apiErr.Status)
	}
}

func asAPIError(err error, target **errs.APIError) bool {
	for err != nil {
		if e, ok := err.(*errs.APIError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestDoSendsTheTokenAndAcceptsBothListShapes(t *testing.T) {
	var gotAuth string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"count":1,"results":[{"id":"a"}]}`))
	}))
	var raw json.RawMessage
	if err := c.Do(context.Background(), "GET", "/assets/assets/", nil, nil, &raw); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotAuth != "Token t" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Token t")
	}
	rows, err := List(raw)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("List returned %d rows, want 1", len(rows))
	}
}

func TestListAllWalksThePages(t *testing.T) {
	calls := 0
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		offset := r.URL.Query().Get("offset")
		switch offset {
		case "":
			// The first page is full, so the walk must continue.
			rows := make([]map[string]any, 1000)
			for i := range rows {
				rows[i] = map[string]any{"id": string(rune('a'+i%26)) + string(rune('0'+i/26))}
			}
			_ = json.NewEncoder(w).Encode(rows)
		default:
			_, _ = w.Write([]byte(`[{"id":"last"}]`))
		}
	}))
	rows, err := c.ListAll(context.Background(), "/assets/assets/")
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(rows) != 1001 {
		t.Fatalf("ListAll returned %d rows, want 1001", len(rows))
	}
	if calls < 2 {
		t.Fatalf("ListAll made %d calls, want at least 2", calls)
	}
}

func TestListAllMergesAnExistingQuery(t *testing.T) {
	// Appending a second '?' makes the later parameters part of the first
	// parameter's value, and the endpoint then answers with a different
	// result set — silently.
	var gotQuery string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}))
	if _, err := c.ListAll(context.Background(), "/assets/assets/?platform=Linux"); err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	q, err := url.ParseQuery(gotQuery)
	if err != nil {
		t.Fatalf("the query was not parseable: %v (%q)", err, gotQuery)
	}
	if q.Get("platform") != "Linux" {
		t.Errorf("platform = %q, want Linux (query: %q)", q.Get("platform"), gotQuery)
	}
	if q.Get("page_size") == "" {
		t.Errorf("page_size was lost (query: %q)", gotQuery)
	}
}

func TestRawSendsTheCallersHeadersAndNoToken(t *testing.T) {
	var gotAuth, gotCustom string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-JMS-AI-Delegation")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	status, raw, err := c.raw(context.Background(), "GET", "/assets/assets/", "a=1",
		nil, map[string]string{"X-JMS-AI-Delegation": "token"}, 5*time.Second)
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if gotAuth != "" {
		t.Errorf("Raw sent the long-lived token: %q", gotAuth)
	}
	if gotCustom != "token" {
		t.Errorf("the caller's header was not sent: %q", gotCustom)
	}
	if !strings.Contains(string(raw), "ok") {
		t.Errorf("the body was not returned: %q", raw)
	}
}

func TestRawIsNotRetried(t *testing.T) {
	// A delegation credential is a single-use nonce. A retried request would
	// come back as a replay, so a retry would turn a transient hiccup into a
	// hard failure.
	calls := 0
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}))
	_, _, _ = c.raw(context.Background(), "GET", "/assets/assets/", "", nil, nil, 5*time.Second)
	if calls != 1 {
		t.Fatalf("Raw made %d calls, want 1", calls)
	}
}

func TestAPIURLAddsThePrefixOnlyOnce(t *testing.T) {
	c := New(Options{BaseURL: "http://bastion"})
	if got := c.apiURL("/assets/assets/"); got != "http://bastion/api/v1/assets/assets/" {
		t.Errorf("apiURL = %q", got)
	}
	if got := c.apiURL("/api/v1/assets/assets/"); got != "http://bastion/api/v1/assets/assets/" {
		t.Errorf("apiURL on an already-prefixed path = %q", got)
	}
	if got := c.apiURL("assets/assets/"); got != "http://bastion/api/v1/assets/assets/" {
		t.Errorf("apiURL on a relative path = %q", got)
	}
}

// The bastion is reached directly, never through the environment's proxy.
//
// Two things are wrong with proxying it: a private address does not belong
// on a public proxy, and every request carries a long-lived API token. It
// is also fragile — a proxy that is not running takes the whole service with
// it, which is not something a bastion client should inherit from whatever
// happens to be in the environment.
func TestTheClientDoesNotUseTheEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	c := New(Options{BaseURL: "http://bastion", Token: "t"})
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the transport is %T, want *http.Transport", c.HTTP.Transport)
	}
	if tr.Proxy != nil {
		t.Error("the client would send bastion traffic through the environment's proxy")
	}
}

// The contracts generate optional fields as pointers. Handing one to the
// converters must read the VALUE -- an address string ("0x14000…") looks
// real, survives the schema check and reaches the wire as garbage.
// (Caught in the ACL tools: the selector type went out as an address.)
func TestShapeConvertersDerefPointerFields(t *testing.T) {
	s := "ids"
	if got := Str(&s); got != "ids" {
		t.Errorf("Str(*string) = %q, want ids", got)
	}
	var nilStr *string
	if got := Str(nilStr); got != "" {
		t.Errorf("Str(nil *string) = %q, want \"\"", got)
	}
	if got := Str(nil); got != "" {
		t.Errorf("Str(nil) = %q, want \"\"", got)
	}
	b := true
	if got := FieldBool(&b); got == nil || *got != true {
		t.Errorf("FieldBool(*bool) = %v, want true", got)
	}
	var nilBool *bool
	if got := FieldBool(nilBool); got != nil {
		t.Errorf("FieldBool(nil *bool) = %v, want nil", got)
	}
	i := int32(7)
	if got := FieldInt32(&i); got == nil || *got != 7 {
		t.Errorf("FieldInt32(*int32) = %v, want 7", got)
	}
	if got := Int32(&i); got != 7 {
		t.Errorf("Int32(*int32) = %d, want 7", got)
	}
	var nilInt *int32
	if got := FieldInt32(nilInt); got != nil {
		t.Errorf("FieldInt32(nil *int32) = %v, want nil", got)
	}
}
