package jms

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The wire values of the generated enums live in TWO tables:
//
//	the GENERATED constants in jms.go (thriftgo's output), and
//	the hand-written WireEnums table in enum_json.go (what MarshalJSON
//	and the schema pins are built from).
//
// A value added to the IDL lands in the first table and not the second —
// and the wire format would then be incomplete while every test stayed
// green. This guard parses the generated file and reconciles the two
// tables mechanically.

// generatedConsts collects the enum constants of one generated file,
// grouped by enum type name: "Status" → {"ok", "warn", "fail"}.
func generatedConsts(t *testing.T, file string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string][]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			ident, ok := vs.Type.(*ast.Ident)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				out[ident.Name] = append(out[ident.Name], strings.TrimPrefix(name.Name, ident.Name+"_"))
			}
		}
	}
	return out
}

// marshalJSONReceivers collects the types that declare a MarshalJSON
// method in one file — the types whose wire form this package pins.
func marshalJSONReceivers(t *testing.T, file string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "MarshalJSON" || fd.Recv == nil {
			continue
		}
		field := fd.Recv.List[0].Type
		if star, ok := field.(*ast.StarExpr); ok {
			field = star.X
		}
		if ident, ok := field.(*ast.Ident); ok {
			out[ident.Name] = true
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	slices.Sort(ac)
	slices.Sort(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// The two tables must name the same values: every generated constant has a
// place in the wire table, and the wire table invents nothing.
func TestTheWireTableMatchesTheGeneratedConstants(t *testing.T) {
	consts := generatedConsts(t, "jms.go")
	for typ, names := range WireEnums {
		typeName := typ.Name()
		want := consts[typeName]
		if len(want) == 0 {
			t.Errorf("the generated file declares no constants of type %s, but the wire table lists %v", typeName, names)
			continue
		}
		if !sameSet(want, names) {
			t.Errorf("the two tables of %s have drifted: wire table %v, generated constants %v", typeName, names, want)
		}
	}
	for typeName, values := range consts {
		found := false
		for typ := range WireEnums {
			if typ.Name() == typeName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the generated file declares %s constants %v, but the wire table has no entry — its wire format is not pinned", typeName, values)
		}
	}
}

// Every enum that marshals as its name is in the wire table, and every
// wire-table entry marshals as its name: the pin and the wire format are
// the same decision.
func TestEveryMarshalJSONTypeIsInTheWireTable(t *testing.T) {
	receivers := marshalJSONReceivers(t, "enum_json.go")
	for name := range receivers {
		found := false
		for typ := range WireEnums {
			if typ.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s marshals as its name but is missing from WireEnums — its schema would say integer", name)
		}
	}
	for typ := range WireEnums {
		if !receivers[typ.Name()] {
			t.Errorf("%s is in WireEnums but declares no MarshalJSON — the pin says string while the wire writes a number", typ.Name())
		}
	}
}

// Every wire value round-trips: it marshals as its name and parses back
// from it.
func TestEveryWireValueRoundTrips(t *testing.T) {
	roundTrip(t, "Status", StatusValues, StatusFromString)
	roundTrip(t, "CommandClass", CommandClassValues, CommandClassFromString)
	roundTrip(t, "Risk", RiskValues, RiskFromString)
	roundTrip(t, "Delivery", DeliveryValues, DeliveryFromString)
}

func roundTrip[T any](t *testing.T, kind string, values []T, from func(string) (T, error)) {
	t.Helper()
	for _, v := range values {
		name := any(v).(interface{ String() string }).String()
		b, err := json.Marshal(v)
		if err != nil {
			t.Errorf("%s(%s) does not marshal: %v", kind, name, err)
			continue
		}
		if string(b) != strconv.Quote(name) {
			t.Errorf("%s(%s) marshals as %s, want the quoted name", kind, name, b)
		}
		got, err := from(name)
		if err != nil {
			t.Errorf("%s name %q does not parse back: %v", kind, name, err)
			continue
		}
		if any(got) != any(v) {
			t.Errorf("%s round-trip changed the value: %v → %v", kind, v, got)
		}
	}
}
