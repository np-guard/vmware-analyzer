package symbolicexpr

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// internalIPTerm represents VMs of a given internal address which is not a segment

// following 4 functions are false since an groupAtomicTerm is a non-empty cond on a group which may or may not hold

func (internalIPTerm) IsTautology() bool {
	return false
}

func (internalIPTerm) IsContradiction() bool {
	return false
}

func (internalIPTerm) IsAllGroups() bool {
	return false
}

func (internalIPTerm) IsNoGroup() bool {
	return false
}

func (internalIP internalIPTerm) String() string {
	prefix := "VMs "
	if internalIP.isNegation() {
		prefix = "not "
	}
	return prefix + "within IPs " + internalIP.ipBlock.OriginalIP
}

func (internalIP internalIPTerm) name() string {
	return internalIP.String()
}

// GetBlock returns nil since the initial block does not guarantee anything regarding the future content of the group
func (internalIPTerm) GetBlock() *netset.IPBlock {
	return nil
}

func (internalIPTerm) AsSelector() (string, bool) {
	return toImplement, false
}

func NewGroupInternalIPTerm(origIP *topology.IPBlock, vms []topology.Endpoint) *internalIPTerm {
	return &internalIPTerm{ipBlock: origIP, vms: vms}
}

func (internalIP internalIPTerm) negate() atomic {
	return internalIPTerm{ipBlock: internalIP.ipBlock, vms: internalIP.vms, atomicTerm: atomicTerm{neg: !internalIP.neg}}
}

// returns true iff otherAtom is negation of internalIP
func (internalIP internalIPTerm) isNegateOf(otherAtom atomic) bool {
	return isNegateOf(internalIP, otherAtom)
}

// returns true iff otherAtom is disjoint to internalIP as given by hints
func (internalIP internalIPTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	if otherAtom.GetBlock() != nil {
		return true // otherAtom is an IPBlock; external IP block is disjoint to group terms referring to VMs
	}
	return disjoint(internalIP, otherAtom, hints)
}

// returns true iff internalIP is superset of otherAtom as given by hints
func (internalIP internalIPTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	return supersetOf(internalIP, otherAtom, hints)
}
