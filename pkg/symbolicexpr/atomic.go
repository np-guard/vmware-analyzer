package symbolicexpr

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

func (term atomicTerm) labelKey() string {
	switch term.property.(type) {
	case *collector.Segment:
		return "segment"
	case *endpoints.VM:
		return "virtual machine"
	case *collector.Tag:
		return "tag " + term.property.Name()
	// includes atomic NSX groups; e.g., groups defined over other entities (such as tags) are not included
	case *collector.Group:
		return "group"
	default: // for structs used for testing
		return term.property.Name()
	}
}

func (term atomicTerm) string() string {
	equalSign := " = "
	if term.neg {
		equalSign = " != "
	}
	return term.labelKey() + equalSign + term.toVal
}
func (term atomicTerm) AsSelector() (string, bool, []string) {
	return term.labelKey(), term.neg, []string{term.toVal}
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

func (tautology) string() string {
	return "*"
}

func (tautology) negate() atomic {
	return tautology{}
}

func (tautology) isTautology() bool {
	return true
}

// returns true iff otherAt is negation of
// once we cache the atomic terms, we can just compare pointers
func (tautology) isNegateOf(atomic) bool {
	return false
}
func (tautology) AsSelector() (string, bool, []string) {
	return "", false, nil
}
