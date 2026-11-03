package jms

// The optional fields of the contract.
//
// A contract's optional fields are pointers so that "absent" and "present
// but empty" are different things on the wire — an absent warning means
// there was nothing to warn about, an empty one would mean the same thing in
// a different spelling.
//
// They are pointers because the IDL says so: a thrift `optional` field is
// nullable, and a nullable field has to be able to say "not there". The
// server checks the answer against the schema before the model sees it, so
// a field that vanishes because the producer forgot it fails at the call
// rather than reaching the agent as a hole.
//
// There is ONE set of these on purpose. The two contract packages used to
// carry their own copies, and the copies had already drifted apart in
// spelling (OptInt vs OptInt32 for the same thing) — a helper that exists in
// two spellings is two helpers.

// Opt returns a pointer to s.
func Opt(s string) *string { return &s }

// OptBool returns a pointer to b.
func OptBool(b bool) *bool { return &b }

// OptInt32 returns a pointer to i.
func OptInt32(i int32) *int32 { return &i }

// OptInt64 returns a pointer to i.
//
// File sizes are 64-bit: a transfer is measured in bytes, and a log file
// does not care about 2^31.
func OptInt64(i int64) *int64 { return &i }

// OptFloat64 returns a pointer to f.
//
// The measured numbers (a walk, a command, a transfer) are durations, and a
// duration has a fraction — so they are doubles, not the integers the rest
// of the counts use.
func OptFloat64(f float64) *float64 { return &f }
