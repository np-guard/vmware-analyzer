package symbolicexpr

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// segmentTerms represents a segment

func NewSegmentTerm(segment *topology.Segment) *segmentTerm {
	return &segmentTerm{segment: segment}
}

func (segment segmentTerm) name() string {
	return segment.segment.Name
}

func (segment segmentTerm) String() string {
	neg := ""
	if segment.isNegation() {
		neg = "not in "
	}
	return neg + "segment " + segment.name()
}

func (segmentTerm) AsSelector() (string, bool) {
	return toImplement, false
}

func (segment segmentTerm) negate() atomic {
	return segmentTerm{segment: segment.segment, atomicTerm: atomicTerm{neg: !segment.neg}}
}

func (segment segmentTerm) isNegateOf(otherAtom atomic) bool {
	return isNegateOf(segment, otherAtom)
}

// returns true iff otherAtom is disjoint to internalIP as given by hints
func (segment segmentTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	// if otherAtom is also an IP Block, then check explicit disjointness
	if isIPDisjoint(segment.getInternalBlock(), otherAtom) {
		return true
	}
	return disjoint(segment, otherAtom, hints)
}

// returns true iff internalIP is superset of otherAtom as given by hints
func (segment segmentTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	// if otherAtom is also an IP Block, then check explicit containment
	if isIPSuperset(segment.getInternalBlock(), otherAtom) {
		return true
	}
	return supersetOf(segment, otherAtom, hints)
}

func (segment segmentTerm) getInternalBlock() *netset.IPBlock {
	return getInternalBlock(segment.segment.Block, segment.isNegation())
}
