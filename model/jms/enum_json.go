package jms

import (
	"encoding/json"
	"fmt"
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
