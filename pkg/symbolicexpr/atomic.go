package symbolicexpr

import (
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

func (term atomicTerm) string() string {
	equalSign := " = "
	if term.neg {
		equalSign = " != "
	}
	labelType := ""
	switch term.property.(type) {
	case *collector.Segment:
		labelType = "segment "
	case *endpoints.VM:
		labelType = "virtual machine "
	case *collector.Tag:
		labelType = "tag " + term.property.Name()
	// includes atomic NSX groups; e.g., groups defined over other entities (such as tags) are not included
	case *collector.Group:
		labelType = "group "
	default: // for structs used for testing
		labelType = term.property.Name()
	}
	return labelType + equalSign + term.toVal
}

func NewAtomicTerm(label vmProperty, toVal string, neg bool) *atomicTerm {
	return &atomicTerm{property: label, toVal: toVal, neg: neg}
}

// negate an atomicTerm expression
func (term atomicTerm) negate() atomic {
	return atomicTerm{property: term.property, toVal: term.toVal, neg: !term.neg}
}

func (atomicTerm) isTautology() bool {
	return false
}

func (term atomicTerm) isNegation() bool {
	return term.neg
}

func (term atomicTerm) name() string {
	return term.toVal
}

// todo: handling only "in group" in this stage
func getAtomicTermsForGroups(groups []*collector.Group) []*atomicTerm {
	res := make([]*atomicTerm, len(groups))
	for i, group := range groups {
		res[i] = &atomicTerm{property: group, toVal: *group.DisplayName, neg: false}
	}
	return res
}

// returns true iff otherAt is negation of
// once we cache the atomic terms, we can just compare pointers
func (term atomicTerm) isNegateOf(otherAt atomic) bool {
	return term.string() == otherAt.negate().string()
}

// returns true iff otherAt is disjoint to atomicTerm as given by hints
// todo: only if of the same type as by (tag/groups/.. as presented by property)?
func (term atomicTerm) disjoint(otherAt atomic, hints *Hints) bool {
	// in hints list of disjoint groups/tags/.. is given. Actual atomicTerms are disjoint only if both not negated
	if term.isNegation() || otherAt.isNegation() {
		return false
	}
	return hints.disjoint(term.name(), otherAt.name())
}

// returns true iff term is implied by to atomic as given by hints
// todo: only if of the same type as by (tag/groups/.. as presented by property)?
func (term atomicTerm) impliedBy(otherAt atomic, hints *Hints) bool {
	// in hints list of disjoint groups/tags/.. is given. Term1 is implied by term2 if both are of the same type
	// (tag/groups/.. as presented by property) and term1 is not negated while term2 is
	// e.g., given that Slytherin and Hufflepuff are disjoint, group = Slytherin implies group != Hufflepuff
	return hints.disjoint(term.toVal, otherAt.name()) && term.isNegation() && !otherAt.isNegation()
}

func (tautology) string() string {
	return "*"
}

func (tautology) name() string {
	return ""
}

func (tautology) negate() atomic {
	return tautology{}
}

func (tautology) isNegation() bool {
	return false
}

func (tautology) isTautology() bool {
	return true
}

// returns true iff otherAt is negation of
// once we cache the atomic terms, we can just compare pointers
func (tautology) isNegateOf(atomic) bool {
	return false
}

// tautology is not disjoint to any atomic term
func (tautology) disjoint(atomic, *Hints) bool {
	return false
}

func (tautology) impliedBy(atom atomic, hints *Hints) bool {
	return atom.isTautology()
}

// are two given by name atomicTerms in disjoint list
func (hints *Hints) disjoint(name1, name2 string) bool {
	if name1 == name2 {
		return false
	}
	for _, disjointGroup := range hints.GroupsDisjoint {
		if slices.Contains(disjointGroup, name1) && slices.Contains(disjointGroup, name2) {
			return true
		}
	}
	return false
}
