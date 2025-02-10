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

func (tagTerm tagAtomicTerm) string() string {
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
	if elem == nil {
		return nil
	}
	conj, ok := elem.(*collector.ConjunctionOperator)
	if !ok {
		return nil
	}
	// assumption: conj is an "Or" or "And" of two conditions on vm's tag (as above)
	if *conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorAND &&
		*conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorOR {
		return nil
	}
	conjunctionOperatorConjunctionOperator := conj.ConjunctionOperator.ConjunctionOperator
	return conjunctionOperatorConjunctionOperator
}

// GetTagConjunctionForExpr returns the []*Conjunction corresponding to an expression - supported in this stage:
// either a single condition or two conditions with ConjunctionOperator in which the condition(s) refer to a tag of a VM
func GetTagConjunctionForExpr(expr *collector.Expression, group string) []*Conjunction {
	const nonTrivialExprLength = 3
	if expr == nil || len(*expr) == 0 {
		return exprNotSupported(expr, group)
	}
	exprVal := *expr
	condTag1 := getTagTermExprElement(exprVal[0])
	if condTag1 == nil {
		return exprNotSupported(expr, group)
	}
	if len(exprVal) == 1 { // single condition of a tag equal or not equal a value
		return []*Conjunction{{condTag1}}
	} else if len(*expr) == nonTrivialExprLength {
		orOrAnd := getConjunctionOperator(exprVal[1])
		condTag2 := getTagTermExprElement(exprVal[2])
		if orOrAnd == nil || condTag2 == nil {
			return exprNotSupported(expr, group)
		}
		if *orOrAnd == resources.ConjunctionOperatorConjunctionOperatorAND {
			return []*Conjunction{{condTag1, condTag2}} // And: single Conjunction
		}
		return []*Conjunction{{condTag1}, {condTag2}} // Or: two Conjunctions
	}
	// len not 1 neither 3
	return exprNotSupported(expr, group)
}

func exprNotSupported(expr *collector.Expression, group string) []*Conjunction {
	logging.Debugf("expr %s of group %s is either illegal or not supported by the POC", expr.String(), group)
	return nil
}

func getTagTermExprElement(elem collector.ExpressionElement) *tagAtomicTerm {
	cond, ok := elem.(*collector.Condition)
	if !ok {
		return nil
	}
	return getTagTermsForCondition(cond)
}
