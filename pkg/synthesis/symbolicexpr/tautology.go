package symbolicexpr

import "github.com/np-guard/models/pkg/netset"

// tautology implementation

func (tautology) String() string {
	return "*"
}

func (tautology) name() string {
	return ""
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

// returns true iff otherAt is negation of
// once we cache the atomic terms, we can just compare pointers
func (tautology) isNegateOf(atom atomic) bool {
	_, isContradict := atom.(contradiction)
	return isContradict
}
func (tautology) AsSelector() (string, bool) {
	return "", false
}

// tautology is not disjoint to any atomic term
func (tautology) disjoint(atomic, *Hints) bool {
	return false
}

func (tautology) supersetOf(atom atomic, hints *Hints) bool {
	return atom.IsTautology()
}

func (tautology) GetBlock() *netset.IPBlock {
	return nil
}
