package symbolicexpr

// contradiction is the negation of tautology

import "github.com/np-guard/models/pkg/netset"

func (contradiction) String() string {
	return "empty set"
}

func (c contradiction) name() string {
	return c.String()
}

func (contradiction) negate() Atomic {
	return tautology{}
}

func (contradiction) isNegation() bool {
	return false
}

func (contradiction) IsTautology() bool {
	return false
}

func (contradiction) IsContradiction() bool {
	return true
}

func (contradiction) IsAllGroups() bool {
	return false
}

func (contradiction) IsNoGroup() bool {
	return true
}

// contradiction negates tautology
func (contradiction) isNegateOf(atom Atomic) bool {
	return atom.IsTautology()
}
func (contradiction) AsSelector() (string, bool) {
	return toImplement, false
}

// contradiction is disjoint to any no-contradiction
func (c contradiction) disjoint(Atomic, *Hints) bool {
	return !c.IsContradiction()
}

// contradiction, which is the empty set, is not a superset of anything
func (c contradiction) supersetOf(atom Atomic, hints *Hints) bool {
	return false
}

func (contradiction) GetExternalBlock() *netset.IPBlock {
	return nil
}

func (contradiction) getInternalBlock() *netset.IPBlock {
	return nil
}

func (contradiction) isInternalOnly() bool {
	return false
}

func (contradiction) IsAllExternal() bool {
	return false
}

func (contradiction) IsSegment() bool {
	return false
}
