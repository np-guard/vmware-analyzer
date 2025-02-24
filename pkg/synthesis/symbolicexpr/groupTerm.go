package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const grp = "group"
const equalSignConst = " = "
const nonEqualSignConst = " != "

func (groupTerm groupAtomicTerm) String() string {
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

func getConjunctionForGroups(groups []*collector.Group, groupToConjunctions map[string][]*Conjunction,
	ruleID int) []*Conjunction {
	res := []*Conjunction{}
	for _, group := range groups {
		// todo: treat negation properly
		if cachedGroupConj, ok := groupToConjunctions[group.Name()]; ok {
			res = append(res, cachedGroupConj...)
			continue
		}
		// not in cache
		// default: Conjunction defined via group only
		groupConj := []*Conjunction{{groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: false}}}}
		synthesisUseGroup := fmt.Sprintf("group %s, referenced by FW rule with ID %d, "+
			"synthesis will be based only on its name", group.Name(), ruleID)
		// if group has a tag based supported expression then considers the tags
		if len(group.Expression) > 0 {
			tagConj := GetTagConjunctionForExpr(&group.Expression, group.Name())
			if tagConj != nil {
				groupConj = tagConj
			} else {
				logging.Debugf("for %s", synthesisUseGroup)
			}
		} else {
			logging.Debugf("No expression is attached to %s", synthesisUseGroup)
		}
		groupToConjunctions[group.Name()] = groupConj
		res = append(res, groupConj...)
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
