package symbolicexpr

import "github.com/np-guard/models/pkg/netset"

// tautology represents *everything* namely 0.0.0.0/0

func (tautology) String() string {
	return "0.0.0.0/0"
}

func (t tautology) name() string {
	return t.String()
}

func (tautology) negate() atomic {
	return contradiction{}
}

func (tautology) isNegation() bool {
	return false
}

func (tautology) IsTautology() bool {
	return true
}

func (tautology) IsContradiction() bool {
	return false
}

func (tautology) IsAllGroups() bool {
	return true
}

func (tautology) IsNoGroup() bool {
	return false
}

// tautology is negation of contradiction
func (tautology) isNegateOf(atom atomic) bool {
	_, isContradict := atom.(contradiction)
	return isContradict
}
func (tautology) AsSelector() (string, bool) {
	return "to implement", false
}

// tautology is not disjoint to any atomic term
func (tautology) disjoint(atomic, *Hints) bool {
	return false
}

func (tautology) supersetOf(atom atomic, hints *Hints) bool {
	return atom.IsTautology()
}

func (tautology) getBlock() *netset.IPBlock {
	return nil
}
