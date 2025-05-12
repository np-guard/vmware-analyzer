package symbolicexpr

// tagTerm represents condition of "tag = xx" or negation of such a condition

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	resources "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

const tagConst = "tag"

// NewTagTerm new tag term
// todo: support scope as well
func NewTagTerm(tagName string, neg bool) *tagAtomicTerm {
	return &tagAtomicTerm{atomicTerm: atomicTerm{neg: neg}, tag: &resources.Tag{Tag: tagName}}
}

func (tagTerm tagAtomicTerm) name() string {
	return tagTerm.tag.Tag
}

func (tagTerm tagAtomicTerm) String() string {
	return tagConst + eqSign(tagTerm) + tagTerm.name()
}

func (tagTerm tagAtomicTerm) AsSelector() (string, bool) {
	return fmt.Sprintf("%s__%s", tagConst, tagTerm.name()), tagTerm.neg
}

// negate an tagAtomicTerm expression
func (tagTerm tagAtomicTerm) negate() atomic {
	return tagAtomicTerm{tag: tagTerm.tag, atomicTerm: atomicTerm{neg: !tagTerm.neg}}
}

// returns true iff otherAt is negation of tagTerm
func (tagTerm tagAtomicTerm) isNegateOf(otherAtom atomic) bool {
	return isNegateOf(tagTerm, otherAtom)
}

// returns true iff otherAt is disjoint to otherAtom as given by hints
func (tagTerm tagAtomicTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	if otherAtom.GetExternalBlock() != nil {
		return true // otherAtom is an IPBlock; external IP block is disjoint to tag terms referring to VMs
	}
	return disjoint(tagTerm, otherAtom, hints)
}

// returns true iff tagTerm is superset of otherAtom as given by hints
func (tagTerm tagAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	return supersetOf(tagTerm, otherAtom, hints)
}

func (tagAtomicTerm) IsSegment() bool {
	return false
}

// evaluates symbolic Conjunctions from a given Expression
//////////////////////////////////////////////////////////

// return the tag corresponding to a given condition
func getAtomicsForCondition(isExcluded bool, cond *collector.Condition, group string) []atomic {
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
	return []atomic{atomicRes}
}

// returns the *conjunctionOperatorConjunctionOperator corresponding to a ConjunctionOperator  - non nested "Or" or "And"
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

func getTermForExprElement(containerModel *collector.ResourcesContainerModel,
	isExcluded bool, elem collector.ExpressionElement, group string) []atomic {
	cond, okCond := elem.(*collector.Condition)
	path, okPath := elem.(*collector.PathExpression)
	switch {
	case okCond:
		return getAtomicsForCondition(isExcluded, cond, group)
	case okPath:
		return getAtomicsForPath(containerModel, isExcluded, path, group)
	default:
		debugMsg(group, fmt.Sprintf("includes a component is of type %T which is not supported", elem))
		return nil
	}
}

func debugMsg(group, text string) {
	logging.Debugf("group's %s defining expression %s ", group, text)
}

// todo this code is here to make the CR easier; needs to be moved to groupBasedInternalResource before merge

// GetConjunctionFromExpr returns the []*Conjunction corresponding to an expression - supported in this stage:
// either a single condition or two conditions with ConjunctionOperator in which the condition(s) refer to a tag of a VM
// gets here only if expression is non-nil and of length > 1
func GetConjunctionFromExpr(containerModel *collector.ResourcesContainerModel,
	isExcluded bool, expr *collector.Expression, group string) []*Conjunction {
	const nonTrivialExprLength = 3
	exprVal := *expr
	condTag1 := getTermForExprElement(containerModel, isExcluded, exprVal[0], group)
	if condTag1 == nil {
		return nil
	}
	if len(exprVal) == 1 { // single condition of a tag equal or not equal a value
		return orAtomicToConjunction(condTag1)
	} else if len(*expr) == nonTrivialExprLength {
		orOrAnd := getConjunctionOperator(isExcluded, exprVal[1], group)
		condTag2 := getTermForExprElement(containerModel, isExcluded, exprVal[2], group)
		if orOrAnd == nil || condTag2 == nil {
			return nil
		}
		if *orOrAnd == resources.ConjunctionOperatorConjunctionOperatorAND {
			return andAtomicToConjunction(condTag1, condTag2)
		}
		return orAtomicToConjunction(append(condTag1, condTag2...))
	}
	// len not 1 neither 3
	debugMsg(group, "is not supported")
	return nil
}

func orAtomicToConjunction(atomics []atomic) []*Conjunction {
	res := make([]*Conjunction, len(atomics))
	for i, thisAtomic := range atomics {
		res[i] = &Conjunction{thisAtomic}
	}
	return res
}

// ANDing a cartesian products of two []atomic
func andAtomicToConjunction(atomics1, atomics2 []atomic) []*Conjunction {
	res := []*Conjunction{}
	for _, atomic1 := range atomics1 {
		for _, atomic2 := range atomics2 {
			res = append(res, &Conjunction{atomic1, atomic2})
		}
	}
	return res
}
