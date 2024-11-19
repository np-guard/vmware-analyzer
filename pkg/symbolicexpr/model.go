package symbolicexpr

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// the package implements a symbolic expression of enabled paths from symbolic src to symbolic dst, expressed as CNF

// Virtual machines' labels used in atomic group expr, e.g. tag = "backend"
// Used by NSX: Tag, Segment, (VM) Name, OS_Name, Computer_Name
// vmLabel implemented by collector.Segment, endpoints.vm, synthesis.Tag
// todo: Support OSName and ComputerName at POC?
type vmLabel interface {
	Name() string
}

// Atomic represent a simple condition, atom of defining a group:
// tag/segment/name(/computer_Name/OS_Name?) equal/not equal string
// formally, Atomic -> label equal const_string, not Atomic
type Atomic struct {
	label vmLabel
	toVal string
	neg   bool
}

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
	_ = atomic
	return nil
}

// Clause a CNF Clause of Atomics
type Clause []*Atomic

// CNFExpr presenting Clauses of Atomics - conditions used for defining a group in NSX
// ToDo: when we simplify CNFExpr, clauses will be translated to map[string]int
type CNFExpr []Clause

// SymbolicSrcDst all path from a Src VM satisfying Src to Dst VM satisfying Dst
type SymbolicSrcDst struct {
	Src CNFExpr
	Dst CNFExpr
}

type SymbolicPaths []SymbolicSrcDst

// Atomics map from Atomics string to *Atomic
type Atomics map[string]*Atomic

// ComputeAllowGivenDenys computes for a given rule the symbolic paths it allows; this is done by unrolling higher priority denies with
// the SymbolicSrcDst of the rule
func ComputeAllowGivenDenys(allowPaths SymbolicSrcDst, denyPaths SymbolicPaths) SymbolicPaths {
	// temp for lint
	_ = allowPaths
	_ = denyPaths
	for _, tmp1 := range denyPaths {
		_, _ = tmp1.Src, tmp1.Dst
		for _, tmp2 := range tmp1.Src {
			for _, tmp3 := range tmp2 {
				_ = tmp3.string()
				_ = tmp3.negate()
			}
		}
	}

	return nil
}
