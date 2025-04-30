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

// evaluates symbolic Conjunctions from a given Expression
//////////////////////////////////////////////////////////

// return the tag corresponding to a given condition
func getAtomicsForCondition(isExcluded bool, cond *collector.Condition, group string) atomic {
	// assumption: cond is of a tag over VMs
	if cond.MemberType == nil || *cond.MemberType != resources.ConditionMemberTypeVirtualMachine ||
		cond.Key == nil || *cond.Key != resources.ConditionKeyTag ||
		cond.Operator == nil {
		debugMsg(group, fmt.Sprintf("contains an NSX condition %s which is not supported", cond.String()))
		return nil
	}
	var neg bool
	if *cond.Operator == resources.ConditionOperatorNOTEQUALS {
		neg = true
	}
	if isExcluded {
		neg = !neg
	}
	tagAtomicTerm := tagAtomicTerm{tag: &resources.Tag{Tag: *cond.Value}, atomicTerm: atomicTerm{neg: neg}}
	var atomicRes atomic = tagAtomicTerm
	return atomicRes
}

// returns the *conjunctionOperatorConjunctionOperator corresponding to a ConjunctionOperator  - non nesterd "Or" or "And"
// if isExcluded: returns "or" for "and" and vice versa (de-morgan)
// returns nil if neither
func getConjunctionOperator(isExcluded bool, elem collector.ExpressionElement,
	group string) *resources.ConjunctionOperatorConjunctionOperator {
	conj, ok := elem.(*collector.ConjunctionOperator)
	if !ok {
		debugMsg(group, fmt.Sprintf("contains an operator of type %T which is not a legal NSX operator", elem))
		return nil
	}
	// assumption: conj is an "Or" or "And" of two conditions on vm's tag (as above)
	if *conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorAND &&
		*conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorOR {
		debugMsg(group, fmt.Sprintf("contains an operator %s which is not supported (yet)", conj.String()))
		return nil
	}
	var retOp = *conj.ConjunctionOperator.ConjunctionOperator
	if isExcluded { // De-Morgan
		if *conj.ConjunctionOperator.ConjunctionOperator == resources.ConjunctionOperatorConjunctionOperatorAND {
			retOp = resources.ConjunctionOperatorConjunctionOperatorOR // And -> Or
		} else {
			retOp = resources.ConjunctionOperatorConjunctionOperatorAND // Or -> And
		}
	}
	return &retOp
}

func getTermForExprElement(isExcluded bool, elem collector.ExpressionElement, group string) atomic {
	cond, okCond := elem.(*collector.Condition)
	path, okPath := elem.(*collector.PathExpression)
	switch {
	case okCond:
		return getAtomicsForCondition(isExcluded, cond, group)
	case okPath:
		//return getAtomicsForPath(isExcluded, path, group)
		getAtomicsForPath(isExcluded, path, group)
		return nil // todo tmp
	default:
		debugMsg(group, fmt.Sprintf("includes a component is of type %T which is not supported", elem))
		return nil
	}

}

func debugMsg(group, text string) {
	logging.Debugf("group's %s defining expression %s ", group, text)
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

// return the tag corresponding to a given condition
func getAtomicsForPath(isExcluded bool, pathExpr *collector.PathExpression, group string) []Atomics {
	res := []Atomics{}
	fmt.Println("pathExpr is", pathExpr)
	return res
}
