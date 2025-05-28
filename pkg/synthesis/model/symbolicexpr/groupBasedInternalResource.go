package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// groupBasedInternalResource represents term over group based internal nsx - groupTerm, tagTerm
func (groupBasedInternalResource) getInternalBlock() *netset.IPBlock {
	return nil
}

// Evaluates group and translates it into DNF
// If group has no expr or evaluation expr fails then uses the group names in the DNF
func getDNFForGroups(config *configuration.Config, isExclude bool, groups []*collector.Group,
	groupToConjunctions map[string][]*Term, ruleID int) DNF {
	res := DNF{}
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
		// default: Term defined via group only
		groupConj := DNF{{groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: isExclude}}}}
		synthesisUseGroup := fmt.Sprintf("group %s, referenced by FW rule with ID %d, "+
			"synthesis will be based only on its name", group.Name(), ruleID)
		// if group has a tag based supported expression then considers the tags
		if len(group.Expression) > 0 {
			tagConj := GetConjunctionFromExpr(config, isExclude, &group.Expression, group.Name())
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

// returns atomic tagAtomicTerm corresponding to a given condition
func getAtomicsForCondition(isExcluded bool, cond *collector.Condition, group string) atomic {
	// assumption: cond is of a tag over VMs
	if cond.MemberType == nil || *cond.MemberType != nsx.ConditionMemberTypeVirtualMachine ||
		cond.Key == nil || *cond.Key != nsx.ConditionKeyTag ||
		cond.Operator == nil {
		debugMsg(group, fmt.Sprintf("contains an NSX condition %s which is not supported", cond.String()))
		return nil
	}
	var neg bool
	if *cond.Operator == nsx.ConditionOperatorNOTEQUALS {
		neg = true
	}
	if isExcluded {
		neg = !neg
	}
	tagAtomicTerm := tagAtomicTerm{tag: &nsx.Tag{Tag: *cond.Value}, atomicTerm: atomicTerm{neg: neg}}
	var atomicRes atomic = tagAtomicTerm
	return atomicRes
}

// returns the *conjunctionOperatorConjunctionOperator corresponding to a ConjunctionOperator  - non nested "Or" or "And"
// if isExcluded: returns "or" for "and" and vice versa (de-morgan)
// returns nil if neither
func getConjunctionOperator(isExcluded bool, elem collector.ExpressionElement,
	group string) *nsx.ConjunctionOperatorConjunctionOperator {
	conj, ok := elem.(*collector.ConjunctionOperator)
	if !ok {
		debugMsg(group, fmt.Sprintf("contains an operator of type %T which is not a legal NSX operator", elem))
		return nil
	}
	// assumption: conj is an "Or" or "And" of two conditions on vm's tag (as above)
	if *conj.ConjunctionOperator.ConjunctionOperator != nsx.ConjunctionOperatorConjunctionOperatorAND &&
		*conj.ConjunctionOperator.ConjunctionOperator != nsx.ConjunctionOperatorConjunctionOperatorOR {
		debugMsg(group, fmt.Sprintf("contains an operator %s which is not supported (yet)", conj.String()))
		return nil
	}
	var retOp = *conj.ConjunctionOperator.ConjunctionOperator
	if isExcluded { // De-Morgan
		if *conj.ConjunctionOperator.ConjunctionOperator == nsx.ConjunctionOperatorConjunctionOperatorAND {
			retOp = nsx.ConjunctionOperatorConjunctionOperatorOR // And -> Or
		} else {
			retOp = nsx.ConjunctionOperatorConjunctionOperatorAND // Or -> And
		}
	}
	return &retOp
}

// return  []*Term which is a symbolic presentation of the expression element
// []*Term{C_1,...C_n} represents c_1 Or C_2 Or.. Or C_n
func getConjunctionsForExprElement(config *configuration.Config, isExcluded bool, group string,
	elem collector.ExpressionElement) []*Term {
	cond, okCond := elem.(*collector.Condition)
	path, okPath := elem.(*collector.PathExpression)
	switch {
	case okCond:
		return []*Term{{getAtomicsForCondition(isExcluded, cond, group)}}
	case okPath:
		return getCojunctionsOfPath(config, isExcluded, path, group)
	default:
		debugMsg(group, fmt.Sprintf("includes a component is of type %T which is not supported", elem))
		return nil
	}
}

func debugMsg(group, text string) {
	logging.Debugf("group's %s defining expression %s ", group, text)
}

// GetConjunctionFromExpr returns the []*Term corresponding to an expression - supported in this stage:
// either a single condition or two conditions with ConjunctionOperator in which the condition(s) refer to a tag of a VM
// gets here only if expression is non-nil and of length > 1
func GetConjunctionFromExpr(config *configuration.Config,
	isExcluded bool, expr *collector.Expression, group string) []*Term {
	exprVal := *expr
	const nonTrivialExprLength = 3
	condTag1 := getConjunctionsForExprElement(config, isExcluded, group, exprVal[0])
	if condTag1 == nil {
		return nil
	}
	if len(exprVal) == 1 { // single condition of a tag equal or not equal a value
		return condTag1
	} else if len(*expr) == nonTrivialExprLength {
		orOrAnd := getConjunctionOperator(isExcluded, exprVal[1], group)
		condTag2 := getConjunctionsForExprElement(config, isExcluded, group, exprVal[2])
		if orOrAnd == nil || condTag2 == nil {
			return nil
		}
		if *orOrAnd == nsx.ConjunctionOperatorConjunctionOperatorAND {
			return andConjunctions(condTag1, condTag2)
		}
		return append(condTag1, condTag2...)
	}
	// len not 1 neither 3
	debugMsg(group, "is not supported")
	return nil
}

// ANDing a cartesian products of two []*Term
func andConjunctions(conjunctions1, conjunctions2 []*Term) []*Term {
	res := []*Term{}
	for _, conj1 := range conjunctions1 {
		for _, conj2 := range conjunctions2 {
			var andConj = *conj1.copy()
			andConj = append(andConj, *conj2...)
			res = append(res, &andConj)
		}
	}
	return res
}

// returns the []*conjunction corresponding to a given condition on []path
// []path represents ORing the paths of the slice
func getCojunctionsOfPath(config *configuration.Config, isExcluded bool, pathExpr *collector.PathExpression,
	group string) []*Term {
	res := []*Term{}
	for _, path := range pathExpr.Paths {
		groupOfPath, isGroup := config.PathToGroupsMap[path]
		segmentOfPath, isSegment := config.PathToSegmentsMap[path]
		switch {
		case isGroup:
			res = append(res, &Term{groupAtomicTerm{group: groupOfPath, atomicTerm: atomicTerm{neg: isExcluded}}})
		case isSegment:
			res = append(res, &Term{SegmentTerm{segment: segmentOfPath, atomicTerm: atomicTerm{neg: isExcluded}}})
		default:
			debugMsg(group, fmt.Sprintf("group %s includes a path %s which is not currently supported "+
				"(currently supported: group or segment) ", group, path))
		}
	}
	return res
}
