package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	resources "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// groupBasedInternalResource represents term over group based internal resources - groupTerm, tagTerm
func (groupBasedInternalResource) getInternalBlock() *netset.IPBlock {
	return nil
}

// Evaluates group and translates it into []*Conjunction
// If group has no expr or evaluation expr fails then uses the group names in  Conjunction
func getConjunctionForGroups(isExclude bool, groups []*collector.Group, groupToConjunctions map[string][]*Conjunction,
	ruleID int) []*Conjunction {
	res := []*Conjunction{}
	for _, group := range groups {
		key := group.Name()
		if isExclude {
			key = "not-" + key
		}
		// todo: treat negation properly
		if cachedGroupConj, ok := groupToConjunctions[key]; ok {
			res = append(res, cachedGroupConj...)
			continue
		}
		// not in cache
		// default: Conjunction defined via group only
		groupConj := []*Conjunction{{groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: isExclude}}}}
		synthesisUseGroup := fmt.Sprintf("group %s, referenced by FW rule with ID %d, "+
			"synthesis will be based only on its name", group.Name(), ruleID)
		// if group has a tag based supported expression then considers the tags
		if len(group.Expression) > 0 {
			tagConj := GetConjunctionFromExpr(isExclude, &group.Expression, group.Name())
			if tagConj != nil {
				groupConj = tagConj
			} else {
				logging.Debugf("for %s", synthesisUseGroup)
			}
		} else {
			logging.Debugf("No expression is attached to %s", synthesisUseGroup)
		}
		groupToConjunctions[key] = groupConj
		res = append(res, groupConj...)
	}
	return res
}

// GetConjunctionFromExpr returns the []*Conjunction corresponding to an expression - supported in this stage:
// either a single condition or two conditions with ConjunctionOperator in which the condition(s) refer to a tag of a VM
// gets here only if expression is non-nil and of length > 1
func GetConjunctionFromExpr(isExcluded bool, expr *collector.Expression, group string) []*Conjunction {
	const nonTrivialExprLength = 3
	exprVal := *expr
	condTag1 := getTermForExprElement(isExcluded, exprVal[0], group)
	if condTag1 == nil {
		return nil
	}
	if len(exprVal) == 1 { // single condition of a tag equal or not equal a value
		if isExcluded {
			return []*Conjunction{{condTag1.negate()}}
		}
		return []*Conjunction{{condTag1}}
	} else if len(*expr) == nonTrivialExprLength {
		orOrAnd := getConjunctionOperator(isExcluded, exprVal[1], group)
		condTag2 := getTermForExprElement(isExcluded, exprVal[2], group)
		if orOrAnd == nil || condTag2 == nil {
			return nil
		}
		if *orOrAnd == resources.ConjunctionOperatorConjunctionOperatorAND {
			return []*Conjunction{{condTag1, condTag2}} // And: single Conjunction
		}
		return []*Conjunction{{condTag1}, {condTag2}} // Or: two Conjunctions
	}
	// len not 1 neither 3
	debugMsg(group, "is not supported")
	return nil
}
