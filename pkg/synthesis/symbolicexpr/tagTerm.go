package symbolicexpr

// tagTerm represents condition of "tag = xx" or negation of such a condition

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
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

// following 4 functions are false since an tagAtomicTerm is a non-empty cond on a tag which may or may not hold

func (tagAtomicTerm) IsTautology() bool {
	return false
}

func (tagAtomicTerm) IsContradiction() bool {
	return false
}

func (tagAtomicTerm) IsAllGroups() bool {
	return false
}

func (tagAtomicTerm) IsNoGroup() bool {
	return false
}

//

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

func (tagAtomicTerm) GetExternalBlock() *netset.IPBlock {
	return nil
}

// evaluates symbolic Conjunctions from a given Expression
//////////////////////////////////////////////////////////

// return the tag corresponding to a given condition
func getTagTermsForCondition(cond *collector.Condition, group string) *tagAtomicTerm {
	// assumption: cond is of a tag over VMs
	if cond.Condition.MemberType == nil || *cond.Condition.MemberType != resources.ConditionMemberTypeVirtualMachine ||
		cond.Condition.Key == nil || *cond.Condition.Key != resources.ConditionKeyTag ||
		cond.Condition.Operator == nil {
		debugMsg(group, fmt.Sprintf("contains an NSX condition %s which is not supported", cond.String()))
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
func getConjunctionOperator(elem collector.ExpressionElement,
	group string) *resources.ConjunctionOperatorConjunctionOperator {
	conj, ok := elem.(*collector.ConjunctionOperator)
	if !ok {
		debugMsg(group, fmt.Sprintf("contains an operator of type %T which is not a legal NSX operator", elem))
	}
	// assumption: conj is an "Or" or "And" of two conditions on vm's tag (as above)
	if *conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorAND &&
		*conj.ConjunctionOperator.ConjunctionOperator != resources.ConjunctionOperatorConjunctionOperatorOR {
		debugMsg(group, fmt.Sprintf("contains an operator %s which is not supported (yet)", conj.String()))
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
		orOrAnd := getConjunctionOperator(exprVal[1], group)
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
	debugMsg(group, "is not supported")
	return nil
}

func getTagTermExprElement(elem collector.ExpressionElement, group string) *tagAtomicTerm {
	cond, ok := elem.(*collector.Condition)
	if !ok {
		debugMsg(group, fmt.Sprintf("includes a component is of type %T which is not supported", elem))
		return nil
	}
	return getTagTermsForCondition(cond, group)
}

func debugMsg(group, text string) {
	logging.Debugf("group's %s defining expression %s ", group, text)
}
