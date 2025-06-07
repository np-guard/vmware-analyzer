package symbolicexpr

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// internalIPTerm represents VMs of a given internal IP address block which is not a segment

func NewInternalIPTerm(ruleBlock *topology.RuleIPBlock, isExclude bool) *internalIPTerm {
	return &internalIPTerm{ruleBlock: ruleBlock, atomicTerm: atomicTerm{neg: isExclude}}
}

func (internalIP internalIPTerm) String() string {
	neg := ""
	if internalIP.isNegation() {
		neg = "not "
	}
	return "VMs " + neg + "within IPs " + internalIP.name()
}

func (internalIP internalIPTerm) name() string {
	return internalIP.ruleBlock.OriginalIP
}

func (internalIP internalIPTerm) AsSelector() (string, bool) {
	return fmt.Sprintf("VMs_within_IPs__%s", strings.ReplaceAll(internalIP.name(), "/", "-")), internalIP.neg
}

func (internalIP internalIPTerm) negate() Atomic {
	return internalIPTerm{ruleBlock: internalIP.ruleBlock, atomicTerm: atomicTerm{neg: !internalIP.neg}}
}

// returns true iff otherAtom is negation of internalIP
func (internalIP internalIPTerm) isNegateOf(otherAtom Atomic) bool {
	return isNegateOf(internalIP, otherAtom)
}

// returns true iff otherAtom is disjoint to internalIP as given by hints
func (internalIP internalIPTerm) disjoint(otherAtom Atomic, hints *Hints) bool {
	// if otherAtom is also an IP Block, then check explicit disjointness
	if isIPDisjoint(internalIP.getInternalBlock(), otherAtom) {
		return true
	}
	return disjoint(internalIP, otherAtom, hints)
}

// returns true iff internalIP is superset of otherAtom as given by hints
func (internalIP internalIPTerm) supersetOf(otherAtom Atomic, hints *Hints) bool {
	// if otherAtom is also an IP Block, then check explicit containment
	if isIPSuperset(internalIP.getInternalBlock(), otherAtom) {
		return true
	}
	return supersetOf(internalIP, otherAtom, hints)
}

func (internalIP internalIPTerm) getInternalBlock() *netset.IPBlock {
	return getInternalBlock(internalIP.ruleBlock.Block, internalIP.isNegation())
}

func (internalIPTerm) IsSegment() bool {
	return false
}

// if otherAtom is also internal Block, then check explicit disjointness
func isIPDisjoint(thisInternalBlock *netset.IPBlock, otherAtom Atomic) bool {
	if otherAtom.GetExternalBlock() != nil {
		return true // otherAtom is an IPBlock; external IP block is disjoint to group terms referring to VMs
	}
	// if otherAtom is also internal Block, then check explicit disjointness
	otherInternalBlock := otherAtom.getInternalBlock()
	if otherInternalBlock != nil {
		if thisInternalBlock.Intersect(otherInternalBlock).IsEmpty() {
			return true
		}
	}
	return false
}

// if otherAtom is also internal Block, then check explicit containment
func isIPSuperset(thisInternalBlock *netset.IPBlock, otherAtom Atomic) bool {
	// if otherAtom is also internal Block, then check explicit disjointness
	otherInternalBlock := otherAtom.getInternalBlock()
	if otherInternalBlock != nil {
		if otherInternalBlock.Intersect(thisInternalBlock.Complementary()).IsEmpty() {
			return true
		}
	}
	return false
}

// gets internal block - considers negation
func getInternalBlock(internalIP *netset.IPBlock, isNegation bool) *netset.IPBlock {
	if isNegation {
		return internalIP.Complementary()
	}
	return internalIP
}
