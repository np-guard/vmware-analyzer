package symbolicexpr

// allExternal represents *all* external IPs

import (
	"github.com/np-guard/models/pkg/netset"
)

func (allExternal) String() string {
	return "IP addr is external"
}

func (allExternal) IsTautology() bool {
	return false
}

func (allExternal) IsAllGroups() bool {
	return false
}

func (allExternal) IsNoGroup() bool {
	return true
}

// IsContradiction true iff the ipBlock is empty
func (allExternal) IsContradiction() bool {
	return false
}

func (allExternal) name() string {
	return "all External IPs"
}

func (allExt allExternal) AsSelector() (string, bool) {
	return toImplement, false
}

// GetExternalBlock allExternal kept only symbolically; GetExternalBlock() just used to symbolize it is external
func (allExternal) GetExternalBlock() *netset.IPBlock {
	return netset.GetCidrAll()
}

// not used for allExternal
func (allExternal) negate() atomic {
	return nil
}

// not used for allExternal
func (allExternal) isNegateOf(otherAtom atomic) bool {
	return false
}

// not used for allExternal
func (allExternal) isNegation() bool {
	return false
}

// returns true iff otherAtom refers to external ips
func (allExternal) disjoint(otherAtom atomic, hints *Hints) bool {
	return otherAtom.GetExternalBlock() == nil
}

// returns true iff otherAtom refers to external ips
func (allExt allExternal) supersetOf(otherAtom atomic, hints *Hints) bool {
	return !allExt.disjoint(otherAtom, hints)
}

func (allExternal) getInternalBlock() *netset.IPBlock {
	return nil
}

func (allExternal) isInternalOnly() bool {
	return false
}

func (allExternal) IsAllExternal() bool {
	return true
}
