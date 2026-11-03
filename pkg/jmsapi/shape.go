package jmsapi

// The shape helpers: how JumpServer's JSON is put together.
//
// v5 mixes several conventions in the same response, and a caller that guesses
// wrong gets a silently wrong answer rather than an error:
//
//   - a list may be a bare JSON array or a {count, results} envelope;
//   - a "choice" field may be a bare value or a {value, label} envelope;
//   - a related object may be nested or flattened into a string label.
//
// These functions are the one place that knows those conventions, so the two
// servers read the same response the same way.

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/oekit/pkg/convert"

	"github.com/yi-nology/jumpserver-mcp-kit/model/jms"
	"github.com/yi-nology/jumpserver-mcp-kit/pkg/textx"
)

// List unpacks both shapes JumpServer v5 returns: a bare JSON array (the API
// has pagination wrapping disabled globally) and a {count, results} envelope.
//
// A response that is neither is an ERROR, not an empty list. The permissive
// reading — "an object without results has no results" — turns a response the
// client did not understand into the claim that the collection is empty, and
// that claim is exactly what a caller reports to a human as "there is nothing
// there". An empty list and an unreadable response are different facts.
func List(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var env struct {
		Count   *int              `json:"count"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &ShapeError{Body: Truncate(string(raw), 160)}
	}
	if env.Count == nil && env.Results == nil {
		return nil, &ShapeError{Body: Truncate(string(raw), 160)}
	}
	return env.Results, nil
}

// EnvelopeCount reads the total a list response says it holds.
//
// It is the number the SERVER counted, which is not the same as the number
// of rows that came back: a paginated response carries both, and they
// differ exactly when the collection is longer than one page.
//
// ⚠️ It returns 0 for a BARE ARRAY (the shape some endpoints answer with)
// and for a response that carries no count -- the caller cannot tell those
// two from "there is nothing there", so a caller that needs the
// distinction has to say what it does when the count is unknown.
//
// The count is read from the LAST page of a walk, so it is the count of
// the WHOLE filtered collection, not of one page.
func EnvelopeCount(raw json.RawMessage) int {
	var env struct {
		Count *int `json:"count"`
	}
	if json.Unmarshal(raw, &env) != nil || env.Count == nil {
		return 0
	}
	return *env.Count
}

// ShapeError is a response that matched none of the shapes v5 is known to
// answer with. It says so explicitly, because the alternative — returning an
// empty list — reads as "there is nothing there", which is a different claim.
type ShapeError struct {
	Body string
}

func (e *ShapeError) Error() string {
	return "unexpected list shape: " + e.Body
}

// Label reads a labelled-choice field, e.g. {"value":"ok","label":"OK"}.
//
// The value is what the API compares on; the label is what the UI shows. A
// caller that wants the label asks for it explicitly.
func Label(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if mm, ok := v.(map[string]any); ok {
		return Str(mm["value"])
	}
	return Str(v)
}

// Display reads the DISPLAY label of a labelled object, where Label reads
// its value.
//
// The two are not interchangeable: a content type comes back as
// {"value": 6, "label": "Asset"}, and "6" tells a caller nothing while
// "Asset" does. Use Label where the value is the thing (a connectivity
// state, a risk class) and Display where a person has to read it.
func Display(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if mm, ok := v.(map[string]any); ok {
		return Str(mm["label"])
	}
	return Str(v)
}

// FieldName reads a related-object field, preferring its name.
//
// A relation may come back as {"id":..,"name":..} or as a bare value; the
// name is what a person reads, so it wins when it is there.
func FieldName(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if mm, ok := v.(map[string]any); ok {
		if n, ok := mm["name"].(string); ok {
			return n
		}
		return Str(mm["value"])
	}
	return Str(v)
}

// AssetField reads an asset's own attribute out of a row that merely refers
// to it.
//
// The bastion points at an asset in two ways: nested, as an object, and flat,
// as a label of the form "name(address)". A row may carry either, so a reader
// that only knows one of them reads nothing.
func AssetField(m map[string]any, attr string) any {
	if mm, ok := m["asset"].(map[string]any); ok {
		return mm[attr]
	}
	switch attr {
	case "id":
		return m["asset_id"]
	case "name", "address":
		s, ok := m["asset"].(string)
		if !ok {
			return nil
		}
		name, addr := SplitAssetLabel(s)
		if attr == "name" {
			return name
		}
		return addr
	}
	return nil
}

// deref unwraps a pointer to the value it points at, and a nil pointer to
// nil.
//
// The contracts generate OPTIONAL fields as pointers (*string, *bool,
// *int32). Handing one of those to a converter that formats `any` prints
// the ADDRESS ("0x14000…") -- a value that looks real, survives every
// schema check, and reaches the wire or the search index as garbage.
// Read a typed field through these converters and the deref happens here,
// once, instead of at fifty call sites.
func deref(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case *string:
		if t == nil {
			return nil
		}
		return *t
	case *bool:
		if t == nil {
			return nil
		}
		return *t
	case *int32:
		if t == nil {
			return nil
		}
		return *t
	case *int:
		if t == nil {
			return nil
		}
		return *t
	case *int64:
		if t == nil {
			return nil
		}
		return *t
	case *float64:
		if t == nil {
			return nil
		}
		return *t
	}
	return v
}

// Str reads a field as a string, and an absent field as "".
//
// convert.AnyToStr turns a missing field into the four characters "<nil>",
// which is worse than nothing: it looks like a value, it survives the schema
// check, and it reaches the model as a name that does not exist. A field
// that is not there has to read as not there.
func Str(v any) string {
	s := convert.AnyToStr(deref(v))
	if s == "<nil>" {
		return ""
	}
	return s
}

// OptStr reads a field as an optional string: absent means absent.
//
// The contracts mark a field optional when the bastion may leave it out, and
// an optional field that is present as "<nil>" is a lie: the caller sees a
// value and cannot tell it from a real one.
func FieldStr(v any) *string {
	s := Str(v)
	if s == "" {
		return nil
	}
	return &s
}

// OptBool reads a field as an optional bool.
func FieldBool(v any) *bool {
	v = deref(v)
	if v == nil {
		return nil
	}
	b := convert.AnyToBool(v)
	return &b
}

// OptInt32 reads a field as an optional 32-bit integer.
//
// The API carries numbers as JSON floats, so a count arrives as 49.0 and has
// to become an int32 before it can go into a contract.
func FieldInt32(v any) *int32 {
	switch t := deref(v).(type) {
	case nil:
		return nil
	case float64:
		i := int32(t)
		return &i
	case float32:
		i := int32(t)
		return &i
	case int:
		i := int32(t)
		return &i
	case int32:
		i := t
		return &i
	case int64:
		i := int32(t)
		return &i
	}
	return nil
}

// Int32 reads a field as a 32-bit integer, and an absent field as 0.
func Int32(v any) int32 {
	v = deref(v)
	if v == nil {
		return 0
	}
	return int32(convert.AnyToInt64(v))
}

// SplitAssetLabel splits the "name(address)" form the bastion uses to refer
// to an asset in a flat row.
func SplitAssetLabel(s string) (name, address string) {
	s = strings.TrimSpace(s)
	open := strings.Index(s, "(")
	closed := strings.LastIndex(s, ")")
	if open < 0 || closed <= open {
		return s, ""
	}
	return strings.TrimSpace(s[:open]), strings.TrimSpace(s[open+1 : closed])
}

// Nested walks a chain of object keys, stopping at the first one that is not
// an object. A missing link yields nil rather than a panic.
func Nested(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

// AsSlice returns a JSON array as a slice, or nil when it is not one.
func AsSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

// Truncate caps a string for display.
//
// It cuts on a rune boundary (the cut lives in pkg/textx, the one place it
// is made): a byte slice would emit invalid UTF-8 into the JSON result,
// where it comes out as a replacement character. The execution plane
// carried a byte-slicing copy of this function for a while, which is the
// whole reason the function moved here and the cut now lives in one place.
func Truncate(s string, n int) string {
	return textx.Trunc(strings.TrimSpace(s), n, "...")
}

// ToMap round-trips a value through JSON into a map.
func ToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

// HTMLToText strips tags and collapses whitespace, which is all a report
// needs. v5 stores free-text fields (an asset's comment, a user's remark) as
// HTML, and that markup is noise in a tool result.
func HTMLToText(b []byte) string {
	t := strings.ReplaceAll(tagRe.ReplaceAllString(string(b), " "), "\n", " ")
	return strings.Join(strings.Fields(t), " ")
}

// AssetSummary turns a raw bastion asset record into the shared asset row.
//
// It lives in the protocol layer because BOTH planes read the same records:
// the management plane's asset list and the execution plane's inventory ask
// the same question ("which machines are there"), so they have to answer it
// in the same words. One helper, one shape, two tools.
func AssetSummary(m map[string]any) jms.AssetSummary {
	out := jms.AssetSummary{
		ID:           Str(m["id"]),
		Name:         Str(m["name"]),
		Address:      Str(m["address"]),
		Platform:     FieldStr(Nested(m, "platform", "name")),
		Connectivity: FieldStr(Label(m, "connectivity")),
		// The category is the bastion's own word for "is this a terminal
		// target": host / web / cloud.
		Category: FieldStr(Nested(m, "category", "value")),
	}
	if n := FieldInt32(m["accounts_amount"]); n != nil {
		out.Accounts = n
	}
	if b := FieldBool(m["is_active"]); b != nil {
		out.IsActive = b
	}
	protos := []string{}
	for _, p := range AsSlice(m["protocols"]) {
		if pm, ok := p.(map[string]any); ok {
			protos = append(protos, Str(pm["name"]))
		}
	}
	if len(protos) > 0 {
		out.Protocols = protos
	}
	return out
}
