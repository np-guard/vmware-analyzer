package symbolicexpr

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

func (term atomicTerm) string() string {
	equalSign := " = "
	if term.neg {
		equalSign = " != "
	}
	labelType := ""
	switch term.label.(type) {
	case *collector.Segment:
		labelType = "segment "
	case *endpoints.VM:
		labelType = "virtual machine "
	case *collector.Tag:
		labelType = "tag "
	}
	return labelType + term.label.Name() + equalSign + term.toVal
}

// negate an atomicTerm expression; return pointer to corresponding expression from Atomics, if not there yet then add it
func (term atomicTerm) negate() atomic {
	return atomicTerm{label: term.label, toVal: term.toVal, neg: !term.neg}
}

func (atomicTerm) isTautology() bool {
	return false
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
