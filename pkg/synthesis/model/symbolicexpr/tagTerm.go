package symbolicexpr

// tagTerm represents condition of "tag = xx" or negation of such a condition

import (
	"fmt"

	resources "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
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
