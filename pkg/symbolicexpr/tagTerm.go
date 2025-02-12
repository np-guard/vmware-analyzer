package symbolicexpr

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const tagConst = "tag"

// todo: support scope as well
func NewTagTerm(tagName string, neg bool) *tagAtomicTerm {
	return &tagAtomicTerm{atomicTerm: atomicTerm{neg: neg}, tag: &resources.Tag{Tag: tagName}}
}

func (tagTerm tagAtomicTerm) name() string {
	return tagTerm.tag.Tag
}

func (tagTerm tagAtomicTerm) String() string {
	equalSign := equalSignConst
	if tagTerm.neg {
		equalSign = nonEqualSignConst
	}
	return tagConst + equalSign + tagTerm.name()
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
	return disjoint(tagTerm, otherAtom, hints)
}

// returns true iff tagTerm is superset of otherAtom as given by hints
func (tagTerm tagAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	return supersetOf(tagTerm, otherAtom, hints)
}

// evaluates symbolic Conjunctions from a given Expression
//////////////////////////////////////////////////////////

// return the tag corresponding to a given condition
func getTagTermsForCondition(cond *collector.Condition) *tagAtomicTerm {
	// assumption: cond is of a tag over VMs
	if cond.Condition.MemberType == nil || *cond.Condition.MemberType != resources.ConditionMemberTypeVirtualMachine ||
		cond.Condition.Key == nil || *cond.Condition.Key != resources.ConditionKeyTag ||
		cond.Condition.Operator == nil {
		logging.Debugf("NSX condition %s not supported", cond.String())
		return nil
	}
	var neg bool
	if *cond.Condition.Operator == resources.ConditionOperatorNOTEQUALS {
		neg = true
	}
	return &tagAtomicTerm{tag: &resources.Tag{Tag: *cond.Value}, atomicTerm: atomicTerm{neg: neg}}
}

// returns the *conjunctionOperatorConjunctionOperator corresponding to a ConjunctionOperator  - non nesterd "Or" or "And"
// returns nil if neither
func getConjunctionOperator(elem collector.ExpressionElement) *resources.ConjunctionOperatorConjunctionOperator {
	conj, ok := elem.(*collector.ConjunctionOperator)
	if !ok {
		logging.Debugf("Type %T is not a legal NSX operator", elem)
	}
	// assumption: conj is an "Or" or "And" of two conditions on vm's tag (as above)
	if *conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorAND &&
		*conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorOR {
		logging.Debugf("NSX operator %v is not supported", conj.String())
		return nil
	}
	conjunctionOperatorConjunctionOperator := conj.ConjunctionOperator.ConjunctionOperator
	return conjunctionOperatorConjunctionOperator
}

// GetTagConjunctionForExpr returns the []*Conjunction corresponding to an expression - supported in this stage:
// either a single condition or two conditions with ConjunctionOperator in which the condition(s) refer to a tag of a VM
// gets here only if expression is non-nil and of length > 1
func GetTagConjunctionForExpr(expr *collector.Expression, group string) []*Conjunction {
	const nonTrivialExprLength = 3
	exprVal := *expr
	condTag1 := getTagTermExprElement(exprVal[0], group)
	if condTag1 == nil {
		return nil
	}
	if len(exprVal) == 1 { // single condition of a tag equal or not equal a value
		return []*Conjunction{{condTag1}}
	} else if len(*expr) == nonTrivialExprLength {
		orOrAnd := getConjunctionOperator(exprVal[1])
		condTag2 := getTagTermExprElement(exprVal[2], group)
		if orOrAnd == nil || condTag2 == nil {
			return nil
		}
		if *orOrAnd == resources.ConjunctionOperatorConjunctionOperatorAND {
			return []*Conjunction{{condTag1, condTag2}} // And: single Conjunction
		}
		return []*Conjunction{{condTag1}, {condTag2}} // Or: two Conjunctions
	}
	// len not 1 neither 3
	logging.Debugf("NSX expression %v is not supported", expr.String())
	return nil
}

func getTagTermExprElement(elem collector.ExpressionElement, group string) *tagAtomicTerm {
	cond, ok := elem.(*collector.Condition)
	if !ok {
		logging.Debugf("group's %s defining expression includes a component is of type %T which is not supported",
			group, elem)
		return nil
	}
	return getTagTermsForCondition(cond)
}
