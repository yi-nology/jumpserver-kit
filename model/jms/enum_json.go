package jms

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// The generated enums carry Thrift's wire semantics (an int64 with a name),
// but this service's contract says the status of a check is the word
// "ok" / "warn" / "fail" — that string is what the agent reads and what the
// skills document. thriftgo emits neither MarshalJSON nor MarshalText for
// enums, so the line format is pinned here, once, instead of in every
// caller that happens to marshal a Diagnosis.
//
// The glue lives next to the generated code on purpose: it is part of the
// wire contract, not an afterthought of some consumer.
//
// ⚠️ The VALUES of every enum are listed here too, and that list is the one
// source the wire format is built from: render's schema pins exactly these
// names (pkg/render.typeSchemas), so "what the schema promises" and "what
// MarshalJSON writes" cannot drift apart. The remaining pair of tables —
// this list against the GENERATED constants in jms.go — is reconciled
// mechanically by the guard in enum_values_test.go: an enum value added to
// the IDL and regenerated shows up as a constant with no place in these
// lists, and the guard goes red.

// StatusValues lists every wire value of Status, in wire order.
var StatusValues = []Status{Status_ok, Status_warn, Status_fail}

// CommandClassValues lists every wire value of CommandClass, in wire order.
var CommandClassValues = []CommandClass{CommandClass_READ, CommandClass_MODIFY, CommandClass_DANGEROUS, CommandClass_UNKNOWN}

// RiskValues lists every wire value of Risk, in wire order.
var RiskValues = []Risk{Risk_read, Risk_write, Risk_destructive}

// DeliveryValues lists every wire value of Delivery, in wire order.
var DeliveryValues = []Delivery{Delivery_not_sent, Delivery_maybe_sent}

// WireEnums maps every generated enum type to its wire value names: the ONE
// table both consumers are built from — the schema pins (pkg/render's
// typeSchemas) and this package's guard (enum_values_test.go, which
// reconciles it against the generated constants and against the
// MarshalJSON receivers). An enum added to the IDL makes the guard go red
// until its values are listed here.
var WireEnums = map[reflect.Type][]string{
	reflect.TypeFor[Status]():       wireNames(StatusValues),
	reflect.TypeFor[CommandClass](): wireNames(CommandClassValues),
	reflect.TypeFor[Risk]():         wireNames(RiskValues),
	reflect.TypeFor[Delivery]():     wireNames(DeliveryValues),
}

// wireNames renders an enum's values as their wire names.
func wireNames[T interface{ String() string }](values []T) []string {
	names := make([]string, len(values))
	for i, v := range values {
		names[i] = v.String()
	}
	return names
}

// MarshalJSON renders the enum as its name.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON parses the enum from its name.
func (s *Status) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("status must be a string like \"ok\": %w", err)
	}
	v, err := StatusFromString(name)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// MarshalJSON renders the enum as its name.
func (c CommandClass) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON parses the enum from its name.
func (c *CommandClass) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("command class must be a string like \"DANGEROUS\": %w", err)
	}
	v, err := CommandClassFromString(name)
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// MarshalJSON renders the enum as its name.
//
// Delivery is the last of the generated enums to get its wire form here:
// every enum of this vocabulary marshals as its name, so a reader never
// has to know which enum happens to sit behind a field.
func (d Delivery) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON parses the enum from its name.
func (d *Delivery) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("delivery must be a string like \"not_sent\": %w", err)
	}
	v, err := DeliveryFromString(name)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// MarshalJSON renders the enum as its name.
func (r Risk) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// UnmarshalJSON parses the enum from its name.
func (r *Risk) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("risk must be a string like \"read\": %w", err)
	}
	v, err := RiskFromString(name)
	if err != nil {
		return err
	}
	*r = v
	return nil
}
