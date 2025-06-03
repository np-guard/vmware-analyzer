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
	groupToDNF map[string]DNF, ruleID int) DNF {
	res := DNF{}
	for _, group := range groups {
		key := group.Name()
		if isExclude {
			key = "not-" + key
		}
		// todo: treat negation properly
		if cachedGroupDNF, ok := groupToDNF[key]; ok {
			res = append(res, cachedGroupDNF...)
			continue
		}
		// not in cache
		// default: Term defined via group only
		groupDNF := DNF{{groupAtomicTerm{group: group, atomicTerm: atomicTerm{neg: isExclude}}}}
		synthesisUseGroup := fmt.Sprintf("group %s, referenced by FW rule with ID %d, "+
			"synthesis will be based only on its name", group.Name(), ruleID)
		// if group has a tag based supported expression then considers the tags
		if len(group.Expression) > 0 {
			tagTerm := GetDNFFromExpr(config, isExclude, &group.Expression, group.Name())
			if tagTerm != nil {
				groupDNF = tagTerm
			} else {
				logging.Debugf("for %s", synthesisUseGroup)
			}
		} else {
			logging.Debugf("No expression is attached to %s", synthesisUseGroup)
		}
		groupToDNF[key] = groupDNF
		res = append(res, groupDNF...)
	}
	return res
}

// evaluates symbolic DNF from a given Expression
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

// return DNF which is a symbolic presentation of the expression element
func getDNFsForExprElement(config *configuration.Config, isExcluded bool, group string,
	elem collector.ExpressionElement) DNF {
	cond, okCond := elem.(*collector.Condition)
	path, okPath := elem.(*collector.PathExpression)
	switch {
	case okCond:
		return DNF{{getAtomicsForCondition(isExcluded, cond, group)}}
	case okPath:
		return getDNFOfPath(config, isExcluded, path, group)
	default:
		debugMsg(group, fmt.Sprintf("includes a component is of type %T which is not supported", elem))
		return nil
	}
}

func debugMsg(group, text string) {
	logging.Debugf("group's %s defining expression %s ", group, text)
}

// GetDNFFromExpr returns the DNF corresponding to an expression []Expression
// its nodes in odd indexes contains a Condition or a NestedExpression
// and in even indexes contains a ConjunctionOperator; it must be of odd size and has at most 5 elements
// It is evaluated from left to right
func GetDNFFromExpr(config *configuration.Config, isExcluded bool, expr *collector.Expression, group string) DNF {
	exprVal := *expr
	var exprDnf = DNF{}
	var lastConjunction *nsx.ConjunctionOperatorConjunctionOperator
	for i, curExprItem := range exprVal {
		if i%2 == 0 { // condition or nested expression
			newExpr := getDNFsForExprElement(config, isExcluded, group, curExprItem)
			if lastConjunction == nil { // first time
				exprDnf = newExpr
			} else if *lastConjunction == nsx.ConjunctionOperatorConjunctionOperatorAND { // And
				exprDnf = andDNFs(exprDnf, newExpr)
			} else if *lastConjunction == nsx.ConjunctionOperatorConjunctionOperatorOR { // Or
				exprDnf = append(exprDnf, newExpr...)
			} else {
				debugMsg(group, "is not supported")
			}
		} else { // Operator
			lastConjunction = getConjunctionOperator(isExcluded, curExprItem, group)
		}
	}
	return exprDnf
}

// ANDing two DNFs
func andDNFs(dnf1, dnf2 DNF) DNF {
	res := DNF{}
	for _, term1 := range dnf1 {
		for _, term2 := range dnf2 {
			var andTerms = *term1.copy()
			andTerms = append(andTerms, *term2...)
			res = append(res, &andTerms)
		}
	}
	return res
}

// returns the DNF corresponding to a given condition on []path
func getDNFOfPath(config *configuration.Config, isExcluded bool, pathExpr *collector.PathExpression,
	group string) DNF {
	res := DNF{}
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
