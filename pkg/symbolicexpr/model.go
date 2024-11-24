package symbolicexpr

// the package implements a symbolic expression of enabled paths from symbolic src to symbolic dst, expressed as CNF

// Virtual machines' labels used in atomic group expr, e.g. tag = "backend"
// Used by NSX: Tag, Segment, (VM) Name, OS_Name, Computer_Name
// vmLabel implemented by collector.Segment, endpoints.vm, synthesis.Tag
// todo: Support OSName and ComputerName at POC?
type vmLabel interface {
	Name() string
}

// atomicTerm represent a simple condition, atom of defining a group:
// tag/segment/name(/computer_Name/OS_Name?) equal/not equal string
// formally, atomicTerm -> label equal const_string, not atomicTerm
type atomicTerm struct {
	label vmLabel
	toVal string
	neg   bool
}

// tautology represents a condition that always holds.
// To be used as src or dst for cases where only dst or only src is restricted
type tautology struct {
}

// atomic interface for atomic expression - implemented by atomicTerm and tautology
type atomic interface {
	string() string
	negate() atomic
}

// Conjunction a DNF Conjunction of Atomics
type Conjunction []atomic

type simplePath struct {
	src atomic
	dst atomic
}

type simplePaths []*simplePath

// SymbolicPath all path from a Src VM satisfying Src to Dst VM satisfying Dst
type SymbolicPath struct {
	Src Conjunction
	Dst Conjunction
}

type SymbolicPaths []*SymbolicPath

// Atomics map from Atomics string to *atomicTerm
type Atomics map[string]atomic

// ComputeAllowGivenDeny converts a set of symbolic allow paths (given as type SymbolicPaths) and a symbolic deny path
// (given an type SymbolicPath) the resulting allow paths in SymbolicPaths
// the motivation here is to unroll allow rule given higher priority deny rule
func ComputeAllowGivenDeny(allowPaths SymbolicPaths, denyPath SymbolicPath) *SymbolicPaths {
	return nil
}
