package symbolicexpr

import "github.com/np-guard/models/pkg/netset"

// allGroups: represents all internal resources (e.g. VMs)
// true for any internal resource (false for external address)
// any tagTerm and groupTerm, internalIPTerm is contained in allGroups
// disjoint to ipBlockTerm (which presents external address)

func (allGroup) String() string {
	return "*"
}

func (ag allGroup) name() string {
	return ag.String()
}

// noGroups is the negation of allGroup
func (allGroup) negate() atomic {
	return noGroup{}
}

func (allGroup) isNegation() bool {
	return false
}

// IsTautology false since allGroup presents only internal resources
func (allGroup) IsTautology() bool {
	return false
}

func (allGroup) IsContradiction() bool {
	return false
}

func (allGroup) IsAllGroups() bool {
	return true
}

func (allGroup) IsNoGroup() bool {
	return false
}

// allGroup is negation of noGroup
func (allGroup) isNegateOf(atom atomic) bool {
	_, isNoGroup := atom.(noGroup)
	return isNoGroup
}
func (allGroup) AsSelector() (string, bool) {
	return toImplement, false
}

// allGroup disjoint to ipBlockTerm which presents external address
func (allGroup) disjoint(atom atomic, hints *Hints) bool {
	return atom.GetExternalBlock() != nil
}

// allGroup is superSet of any groupTerm and of any tagTerm
func (allGroup) supersetOf(atom atomic, hints *Hints) bool {
	return atom.isInternalOnly()
}

func (allGroup) GetExternalBlock() *netset.IPBlock {
	return nil
}

func (allGroup) getInternalBlock() *netset.IPBlock {
	return netset.GetCidrAll()
}

func (allGroup) isInternalOnly() bool {
	return true
}

func (allGroup) IsAllExternal() bool {
	return false
}
