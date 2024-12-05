package symbolicexpr

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

func (atomic atomicTerm) string() string {
	equalSign := " = "
	if atomic.neg {
		equalSign = " != "
	}
	labelType := ""
	switch atomic.label.(type) {
	case *collector.Segment:
		labelType = "segment "
	case *endpoints.VM:
		labelType = "virtual machine "
	case *collector.Tag:
		labelType = "tag "
	}
	return labelType + atomic.label.Name() + equalSign + atomic.toVal
}

// negate an atomicTerm expression; return pointer to corresponding expression from Atomics, if not there yet then add it
func (atomic atomicTerm) negate() atomic {
	return atomicTerm{label: atomic.label, toVal: atomic.toVal, neg: !atomic.neg}
}

func (atomicTerm) isTautology() bool {
	return false
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
