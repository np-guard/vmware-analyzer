package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// segmentTerms represents a segment

func NewSegmentTerm(segment *topology.Segment) *SegmentTerm {
	return &SegmentTerm{segment: segment}
}

func (segment SegmentTerm) name() string {
	return segment.segment.Name
}

func (segment SegmentTerm) String() string {
	neg := ""
	if segment.isNegation() {
		neg = "not in "
	}
	return neg + "segment " + segment.name()
}

func (segment SegmentTerm) AsSelector() (string, bool) {
	return fmt.Sprintf("in_Segment__%s", segment.name()), segment.neg
}

func (segment SegmentTerm) negate() atomic {
	return SegmentTerm{segment: segment.segment, atomicTerm: atomicTerm{neg: !segment.neg}}
}

func (segment SegmentTerm) isNegateOf(otherAtom atomic) bool {
	return isNegateOf(segment, otherAtom)
}

// returns true iff otherAtom is disjoint to internalIP as given by hints
func (segment SegmentTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	// if otherAtom is also an IP Block, then check explicit disjointness
	if isIPDisjoint(segment.getInternalBlock(), otherAtom) {
		return true
	}
	return disjoint(segment, otherAtom, hints)
}

// returns true iff internalIP is superset of otherAtom as given by hints
func (segment SegmentTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	// if otherAtom is also an IP Block, then check explicit containment
	if isIPSuperset(segment.getInternalBlock(), otherAtom) {
		return true
	}
	return supersetOf(segment, otherAtom, hints)
}

func (segment SegmentTerm) getInternalBlock() *netset.IPBlock {
	return getInternalBlock(segment.segment.Block, segment.isNegation())
}

func (SegmentTerm) IsSegment() bool {
	return true
}
