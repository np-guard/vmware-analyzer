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

func (groupAtomicTerm) IsTautology() bool {
	return false
}

func (groupTerm groupAtomicTerm) isNegation() bool {
	return groupTerm.neg
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
// todo: only if of the same type as by (tag/groups/.. as presented by property)?
func (groupTerm groupAtomicTerm) disjoint(otherAt atomic, hints *Hints) bool {
	// in hints list of disjoint groups/tags/.. is given. Actual atomicTerms are disjoint only if both not negated
	if groupTerm.isNegation() || otherAt.isNegation() {
		return false
	}
	return hints.disjoint(groupTerm.name(), otherAt.name())
}

// returns true iff term is superset of groupTerm other as given by hints
// in hints list of disjoint groups/tags/.. is given. Term1 is superset by term2 if they are disjoint and
// term1 is not negated while term2 is
// e.g., given that Slytherin and Hufflepuff are disjoint, group != Hufflepuff is a superset of group = Slytherin
// if in the same Clause, we can rid group != Hufflepuff
// todo: perhaps this can have a general implementation instead of struct specific one
func (groupTerm groupAtomicTerm) supersetOf(otherAt atomic, hints *Hints) bool {
	return hints.disjoint(groupTerm.name(), otherAt.name()) && groupTerm.isNegation() && !otherAt.isNegation()
}
