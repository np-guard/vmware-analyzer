package symbolicexpr

// groupTerm represents condition of "group = xx" or negation of such a condition

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
)

const grp = "group"
const equalSignConst = " = "
const nonEqualSignConst = " != "

func (groupTerm groupAtomicTerm) String() string {
	return grp + eqSign(groupTerm) + groupTerm.name()
}

func (groupTerm groupAtomicTerm) AsSelector() (string, bool) {
	return fmt.Sprintf("%s__%s", grp, groupTerm.name()), groupTerm.neg
}

func NewGroupAtomicTerm(group *collector.Group, neg bool) *groupAtomicTerm {
	return &groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: neg}}
}

// negate an groupAtomicTerm expression
func (groupTerm groupAtomicTerm) negate() Atomic {
	return groupAtomicTerm{group: groupTerm.group, atomicTerm: atomicTerm{neg: !groupTerm.neg}}
}

func (groupTerm groupAtomicTerm) name() string {
	return groupTerm.group.Name()
}

// returns true iff otherAtom is negation of groupTerm
// once we cache the atomic terms, we can just compare pointers
func (groupTerm groupAtomicTerm) isNegateOf(otherAtom Atomic) bool {
	return isNegateOf(groupTerm, otherAtom)
}

// returns true iff otherAtom is disjoint to groupTerm as given by hints
func (groupTerm groupAtomicTerm) disjoint(otherAtom Atomic, hints *Hints) bool {
	if otherAtom.GetExternalBlock() != nil {
		return true // otherAtom is an IPBlock; external IP block is disjoint to group terms referring to VMs
	}
	return disjoint(groupTerm, otherAtom, hints)
}

// returns true iff groupTerm is superset of otherAtom as given by hints
func (groupTerm groupAtomicTerm) supersetOf(otherAtom Atomic, hints *Hints) bool {
	return supersetOf(groupTerm, otherAtom, hints)
}

func (groupAtomicTerm) IsSegment() bool {
	return false
}
