package symbolicexpr

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

// Conjunction a DNF Conjunction of Atomics
type Conjunction []*Atomic

type simplePath struct {
	src *Atomic
	dst *Atomic
}

type simplePaths []*simplePath

// SymbolicPath all path from a Src VM satisfying Src to Dst VM satisfying Dst
type SymbolicPath struct {
	Src Conjunction
	Dst Conjunction
}

type SymbolicPaths []*SymbolicPath

// Atomics map from Atomics string to *Atomic
type Atomics map[string]*Atomic

// ComputeAllowGivenDeny converts a set of symbolic allow paths (given as type SymbolicPaths) and a symbolic deny path
// (given an type SymbolicPath) the resulting allow paths in SymbolicPaths
// the motivation here is to unroll allow rule given higher priority deny rule
func ComputeAllowGivenDeny(allowPaths SymbolicPaths, denyPath SymbolicPath) *SymbolicPaths {
	return nil
}
