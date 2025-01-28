package symbolicexpr

import (
	"fmt"
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const tagConst = "tag"

// todo: support scope as well
func newTagTerm(tagName string, neg bool) *tagAtomicTerm {
	return &tagAtomicTerm{atomicTerm: atomicTerm{neg: neg}, tag: &resources.Tag{Tag: tagName}}
}

func (tagTerm tagAtomicTerm) name() string {
	return tagTerm.tag.Tag
}

func (tagTerm tagAtomicTerm) string() string {
	equalSign := " = "
	if tagTerm.neg {
		equalSign = " != "
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
