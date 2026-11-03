package jmsapi

// What the deployment CAN DO, as opposed to which release it is.
//
// Why this is not "the version": a version says "which release", and a
// capability says "what can be done here". The second is the one a caller
// can act on, the one a difference can be written down as, and the one that
// does not change shape when a new JumpServer release arrives.
//
// The whole difference between JumpServer v4 and v5, as far as this
// repository is concerned, is ONE capability: the Chat AI delegation
// scheme. v4 does not implement it (there is no chat_ai application in v4's
// tree, no X-JMS-AI-Delegation authentication class and no chat-ai API
// prefix). Everything else — the endpoint table, the authentication header,
// the connection-token body, the response shapes — is the same on both, and
// that was checked against the upstream v4.10.20-lts source (see
// version.go).
//
// So the difference is written down ONCE, here, and nowhere else:
//
//   - capabilityDecls says which versions have which capability;
//   - the mechanical guard in internal/arch reads capabilityDecls, so it
//     cannot fall behind the implementation the way a hand-kept list of
//     function names can — with ONE caveat, stated below rather than
//     glossed over: SchemeCalls is still a list of NAMES, and a name can
//     go stale. The guard asserts that every name in it still exists, so a
//     stale entry is a LOUD failure instead of a silent one.
//
// ⇒ Adding a difference between two JumpServer versions means adding one
// row here. Not a version check in the tool layer, not a sentence in three
// doctors, and not a name in the guard.
//
// ⚠️ The version still exists, and it is still what the OPERATOR configures
// (JUMPSERVER_VERSION=v4|v5): it is the one thing they know about their
// deployment. But it is an INPUT, not a question the code asks. The code
// asks "does this deployment have the delegation scheme?" and the answer
// comes from the table.

// Capability is one thing a deployment may or may not have.
type Capability string

const (
	// CapDelegation is the Chat AI delegation scheme: a one-shot credential
	// bound to a single call, which lets an agent act as a specific user
	// without a long-lived token that can do anything.
	//
	// v5 has it. v4 does not implement it at all.
	CapDelegation Capability = "chat_ai_delegation"
)

// CapabilityDecl is everything the repository knows about ONE capability.
//
// Three things hang off it, and they are the three places the knowledge used
// to be duplicated:
//
//   - Versions: which releases have it — the difference itself;
//   - SchemeCalls: which functions PRESENT it — what the guard watches;
//   - the prose below: what its absence changes — what the callers say.
type CapabilityDecl struct {
	// Capability is the name.
	Capability Capability

	// Name is the capability's name in prose ("Chat AI delegation
	// scheme").
	//
	// ⚠️ It is here because every sentence about the capability has to
	// NAME it, and the sentences used to spell the name out at each call
	// site — four places, two spellings. ⇒ The prose is built from this
	// one name, so a reader meets the same words everywhere.
	Name string

	// Const is the Go identifier of this capability's constant
	// ("CapDelegation").
	//
	// ⚠️ It is here for the mechanical guard: it has to recognise "a
	// question about THIS capability" at a call site, and a name is the
	// only thing a syntax tree can match on. ⇒ The guard does not keep a
	// list of its own — it reads this one — so a new capability cannot be
	// added without the guard learning to watch it.
	Const string

	// Versions are the releases that HAVE this capability.
	//
	// ⚠️ The direction matters: a capability that only OLDER versions have
	// is written the same way — the list of versions that have it. What
	// the capability costs when it is missing is written in
	// capabilityCost, and it is the same for every version: a deployment
	// that does not have a capability simply does not have it.
	Versions []Version

	// SchemeCalls are the functions that PRESENT this capability's
	// credential to the bastion.
	//
	// The guard reads this list, so a call site added without asking
	// whether the deployment has the capability is caught — and the guard
	// cannot fall behind, because there is no second list to keep in step.
	SchemeCalls []string

	// Cost is what the absence of this capability costs: one sentence, used
	// by every caller that has to explain it.
	//
	// ⚠️ ONE text, several readers: the two doctors and the three
	// delegation tools all have to say the same thing about "there is no
	// narrower credential here" — and when each of them wrote its own
	// sentence, they drifted. (The execution plane has no sentence of its
	// own: it has no user-facing answer to phrase, only a doctor line.)
	Cost string
}

// capabilityDecls is THE difference list.
//
// ⚠️ It is the only place in the repository that says what differs between
// two JumpServer versions. Everything else asks about capabilities.
var capabilityDecls = []CapabilityDecl{
	{
		Capability:  CapDelegation,
		Name:        "Chat AI delegation scheme",
		Const:       "CapDelegation",
		Versions:    []Version{VersionV5},
		SchemeCalls: []string{"DelegationRequest", "MintDelegation", "SendWithDelegation"},
		Cost: "sessions and calls run with the API credential's own authority " +
			"(an administrator on this deployment) instead of a delegated user's",
	},
}

// CapabilityDeclarations returns the difference list.
//
// It is exported for the mechanical guard in internal/arch, which watches the
// call sites of every capability's scheme and requires them to ask first.
// The guard reads the list from HERE rather than keeping its own copy — so
// there is no second list to keep in step.
//
// ⚠️ It is still a list of NAMES, and a name can go stale: rename the
// function and the list points at nothing, the guard matches no call site,
// checks nothing, and reports green — the worst way for a guard to fail.
// ⇒ That is why the guard ALSO asserts that every name in the list still
// names a function somebody declares (internal/arch's
// TestTheWatchListNamesRealFunctions): a stale entry is loud, not silent.
func CapabilityDeclarations() []CapabilityDecl {
	out := make([]CapabilityDecl, len(capabilityDecls))
	copy(out, capabilityDecls)
	return out
}

// capabilitiesOf returns the capabilities one version has.
func capabilitiesOf(v Version) map[Capability]bool {
	out := map[Capability]bool{}
	for _, decl := range capabilityDecls {
		for _, ver := range decl.Versions {
			if ver == v {
				out[decl.Capability] = true
				break
			}
		}
	}
	return out
}

// declOf returns the declaration of one capability.
func declOf(cap Capability) (CapabilityDecl, bool) {
	for _, decl := range capabilityDecls {
		if decl.Capability == cap {
			return decl, true
		}
	}
	return CapabilityDecl{}, false
}

// CapabilityState is what is known about one capability.
type CapabilityState int

const (
	// CapabilityAbsent: the deployment does not have it.
	CapabilityAbsent CapabilityState = iota
	// CapabilityPresent: the deployment has it.
	CapabilityPresent
	// CapabilityUnknown: it could not be established.
	CapabilityUnknown
)

// String renders the state.
func (s CapabilityState) String() string {
	switch s {
	case CapabilityPresent:
		return "present"
	case CapabilityAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// Profile is what the deployment HAS.
//
// It is resolved once and remembered: the answer decides whether a
// credential is presented, and presenting one costs a request — so the
// answer is not asked twice.
type Profile struct {
	// version is the release the profile was derived from, and known says
	// whether it is known at all.
	version Version
	known   bool
}

// ProfileOf builds a profile from a version.
func profileOf(v Version) Profile {
	return Profile{version: v, known: true}
}

// unknownProfile is the profile of a deployment that could not be asked.
func unknownProfile() Profile {
	return Profile{known: false}
}

// MayPresent reports whether this capability's credential may be presented.
//
// ⚠️ It is the ONE gate every presenting call site uses, and UNKNOWN counts
// as PRESENT — deliberately, because the two ways to be wrong are not
// equally bad:
//
//   - assuming the capability is ABSENT when it is there => every session
//     runs with the API credential's authority instead of a delegated
//     user's => the authority is silently WIDER;
//   - assuming it is PRESENT when it is not => the credential comes back
//     401, a 401 on that path is read as "the fast path is unavailable",
//     and every session then walks the slow koko terminal path => the
//     sessions are SLOWER.
//
// ⇒ "wider but working" is the worse of the two, so unknown counts as
// present.
//
// ⚠️ And the choice is not a coin flip, because the two cases are not
// equally likely:
//
//   - the scheme's ABSENCE is detected DEFINITIVELY: a v4 deployment does
//     not register the chat-ai prefix at all, and the probe compares the
//     prefix's answer with a known-missing path's (see version.go), so
//     "absent" is a finding rather than a guess;
//   - the UNKNOWN case means the probe could not be completed at all, and
//     the scheme's AUTHENTICATION CLASS is registered globally,
//     independently of the API route the probe asks about. ⇒ A v5
//     deployment whose probe route is broken still has a working
//     delegation scheme, and assuming "absent" there would widen every
//     session for nothing.
//
// ⇒ Setting JUMPSERVER_VERSION explicitly removes the question entirely: a
// configured version needs no probe at all.
func (p Profile) MayPresent(cap Capability) bool {
	return p.State(cap) != CapabilityAbsent
}

// Present reports whether the deployment is KNOWN to have the capability.
//
// ⚠️ It is NOT the negation of MayPresent, and the difference is the whole
// point of the three states:
//
//   - Present: known to have it;
//   - MayPresent: not known to lack it (so: known to have it, OR unknown);
//   - neither: known to lack it.
//
// ⇒ A caller that must not act on a capability it has not confirmed asks
// Present; a caller that prefers a working-but-wider answer over a slower
// one asks MayPresent. The two policies are real, they differ, and each is
// written down where it is chosen.
func (p Profile) Present(cap Capability) bool {
	return p.State(cap) == CapabilityPresent
}

// ⚠️ There is deliberately NO `Has(cap)` here, and its absence is the point.
//
// A boolean that answers "does the deployment have it?" has to fold "it does
// not" and "we did not find out" into one answer, and the two callers then
// read the same false differently:
//
//   - a GATE wants "not known to be present" ⇒ refuse to present;
//   - a REPORT wants "not present" ⇒ say the deployment has no scheme.
//
// The same false therefore means opposite things to the two kinds of caller,
// and a report that takes it for "not present" states a fact it has not
// established. ⇒ That is not hypothetical: it is what a doctor did, telling
// an operator that a deployment has no delegation scheme when the probe had
// merely failed.
//
// ⇒ So the fact is asked as a THREE-VALUED question (State) and the decision
// is asked as its own question (MayPresent). A caller that wants to report
// must switch on all three states, because "we do not know" is one of them.
func (p Profile) State(cap Capability) CapabilityState {
	if !p.known {
		return CapabilityUnknown
	}
	if capabilitiesOf(p.version)[cap] {
		return CapabilityPresent
	}
	return CapabilityAbsent
}

// Reason states, in one place, what is known about a capability in a given
// state.
//
// ⚠️ It is one function so that no caller can phrase it its own way: the two
// doctors and the delegation tools all have to say the same thing about
// "there is no narrower credential here", and when each of them wrote its
// own sentence they drifted.
//
// ⚠️ It states the FACT only. What the caller then DOES about it is its own
// decision, and the two decisions differ:
//
//   - the execution plane treats an unknown capability as available (the
//     sessions stay narrow, at the price of the slow path on a deployment
//     that lacks the scheme);
//   - the delegation tools treat it as unavailable (there is nothing to mint
//     a credential for, so the answer says so).
//
// ⇒ The policy sentence lives at the call site; the fact lives here, once.
func Reason(cap Capability, state CapabilityState) string {
	decl, ok := declOf(cap)
	if !ok {
		return ""
	}
	switch state {
	case CapabilityPresent:
		// Nothing to report: the capability is there.
		return ""
	case CapabilityAbsent:
		return "this deployment has no " + decl.Name
	default:
		return "it could not be established whether this deployment has the " + decl.Name
	}
}

// Advice tells the operator what to do about a capability in a given state.
//
// ⚠️ It is the second half of Reason, and it is separate because the two
// halves are used by different callers: a doctor row shows the fact and the
// advice side by side, while a tool that only refuses shows the fact.
//
// The two states call for different actions, and that difference IS the
// advice:
//
//   - absent: nothing can be configured into existence — use another way;
//   - unknown: the answer is one setting away — name it.
func Advice(cap Capability, state CapabilityState) string {
	if _, ok := declOf(cap); !ok {
		return ""
	}
	switch state {
	case CapabilityPresent:
		return ""
	case CapabilityAbsent:
		return "there is nothing to configure into existence here — use the ordinary API " +
			"credential (JUMPSERVER_TOKEN) instead"
	default:
		return "check that JUMPSERVER_URL points at the bastion, or set JUMPSERVER_VERSION=v4 or v5 " +
			"to answer the question without a probe"
	}
}

// Explain states the fact and what the missing capability costs, in one
// string.
//
// ⚠️ It is the sentence for the callers that have ONE place to put the
// answer (a tool's error, a doctor's line). The callers that have two places
// (a doctor row with a separate advice column) use Reason and Advice
// directly.
//
// ⇒ The cost is attached to the ABSENT state only: an unknown capability
// costs nothing yet — nothing has been decided either way.
func Explain(cap Capability, state CapabilityState) string {
	reason := Reason(cap, state)
	switch state {
	case CapabilityPresent:
		return ""
	case CapabilityAbsent:
		return reason + ", so " + CostOf(cap)
	default:
		return reason
	}
}

// Version returns the release the profile was derived from, and whether it
// is known at all.
func (p Profile) Version() (Version, bool) {
	return p.version, p.known
}

// CostOf explains what a capability's absence costs, in one sentence.
//
// It is the same sentence for every caller, because it is the same fact:
// ⚠️ the wording used to be written out separately in the two doctors, the
// delegation tools and the execution plane, and it drifted.
func CostOf(cap Capability) string {
	if decl, ok := declOf(cap); ok {
		return decl.Cost
	}
	return ""
}
