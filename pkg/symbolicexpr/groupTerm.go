package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const grp = "group"
const equalSignConst = " = "
const nonEqualSignConst = " != "

func (groupTerm groupAtomicTerm) string() string {
	equalSign := equalSignConst
	if groupTerm.neg {
		equalSign = nonEqualSignConst
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

func getConjunctionForGroups(groups []*collector.Group) []*Conjunction {
	res := []*Conjunction{}
	for _, group := range groups {
		// if group has a tag based supported expression then considers the tags instead of the group
		if group.Expression != nil && len(group.Expression) > 0 {
			tagConj := GetTagConjunctionForExpr(&group.Expression, group.Name())
			if tagConj != nil {
				res = append(res, tagConj...)
				continue
			}
		} else {
			logging.Debugf("No expression is attached to group %s. Synthesis will thus use only group name",
				group.Name())
		}
		// todo: treat negation properly
		res = append(res, &Conjunction{groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: false}}})
	}
	return res
}

// returns true iff otherAtom is negation of groupTerm
// once we cache the atomic terms, we can just compare pointers
func (groupTerm groupAtomicTerm) isNegateOf(otherAtom atomic) bool {
	return isNegateOf(groupTerm, otherAtom)
}

// returns true iff otherAtom is disjoint to groupTerm as given by hints
func (groupTerm groupAtomicTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	return disjoint(groupTerm, otherAtom, hints)
}

// returns true iff groupTerm is superset of otherAtom as given by hints
func (groupTerm groupAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	return supersetOf(groupTerm, otherAtom, hints)
}
