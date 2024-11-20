package symbolicexpr

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

func (atomic *Atomic) string() string {
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

// negate an Atomic expression; return pointer to corresponding expression from Atomics, if not there yet then add it
func (atomic *Atomic) negate() *Atomic {
	return &Atomic{label: atomic.label, toVal: atomic.toVal, neg: !atomic.neg}
}
