package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
)

const grp = "group"

func (groupTerm groupAtomicTerm) string() string {
	equalSign := " = "
	if groupTerm.neg {
		equalSign = " != "
	}
	return grp + equalSign + groupTerm.name()
}
func (groupTerm groupAtomicTerm) AsSelector() (string, bool) {
	return fmt.Sprintf("%s__%s", grp, groupTerm.name()), groupTerm.neg
}

func NewGroupAtomicTerm(group *collector.Group, neg bool) *groupAtomicTerm {
	return &groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: neg}}
}

// negate an groupAtomicTerm expression
func (groupTerm groupAtomicTerm) negate() atomic {
	return groupAtomicTerm{group: groupTerm.group, atomicTerm: atomicTerm{neg: !groupTerm.neg}}
}

func (groupTerm groupAtomicTerm) name() string {
	return groupTerm.group.Name()
}

// todo: treat negation properly
func getAtomicTermsForGroups(groups []*collector.Group) []*groupAtomicTerm {
	res := make([]*groupAtomicTerm, len(groups))
	for i, group := range groups {
		res[i] = &groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: false}}
	}
	return res
}

// returns true iff otherAt is negation of
// once we cache the atomic terms, we can just compare pointers
func (groupTerm groupAtomicTerm) isNegateOf(otherAtom atomic) bool {
	return isNegateOf(groupTerm, otherAtom)
}

// returns true iff otherAt is disjoint to groupAtomicTerm as given by hints
func (groupTerm groupAtomicTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	return disjoint(groupTerm, otherAtom, hints)
}

// returns true iff term is superset of groupTerm other as given by hints
func (groupTerm groupAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	return supersetOf(groupTerm, otherAtom, hints)
}
