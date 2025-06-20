package symbolicexpr

import "github.com/np-guard/models/pkg/netset"

// noGroups: negation of allGroups: no internal resources (e.g. VMs)
// true for any internal resource (false for external address)
// any tagTerm and groupTerm is contained in allGroups
// disjoint to ipBlockTerm (which presents external address)

func (noGroup) String() string {
	return "no internal resource"
}

func (ng noGroup) name() string {
	return ng.String()
}

// allGroup is the negation of noGroup
func (noGroup) negate() Atomic {
	return allGroup{}
}

func (noGroup) isNegation() bool {
	return false
}

func (noGroup) IsTautology() bool {
	return false
}

// IsContradiction is false for noGroup since noGroup may represent external address
func (noGroup) IsContradiction() bool {
	return false
}

func (noGroup) IsAllGroups() bool {
	return false
}

func (noGroup) IsNoGroup() bool {
	return true
}

// noGroup is negation of allGroup
func (noGroup) isNegateOf(atom Atomic) bool {
	_, isAllGroup := atom.(allGroup)
	return isAllGroup
}
func (noGroup) AsSelector() (string, bool) {
	return toImplement, false
}

// noGroup disjoint to tagTerm and to groupTerm
func (noGroup) disjoint(atom Atomic, hints *Hints) bool {
	return atom.isInternalOnly()
}

// noGroup is not a superset of anything
func (noGroup) supersetOf(atom Atomic, hints *Hints) bool {
	return false
}

func (noGroup) GetExternalBlock() *netset.IPBlock {
	return nil
}

func (noGroup) getInternalBlock() *netset.IPBlock {
	return nil
}

func (noGroup) isInternalOnly() bool {
	return false
}

func (noGroup) IsAllExternal() bool {
	return false
}

func (noGroup) IsSegment() bool {
	return false
}
