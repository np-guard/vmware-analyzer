package symbolicexpr

import "github.com/np-guard/models/pkg/netset"

// the package implements a symbolic expression of enabled paths from symbolic src to symbolic dst, expressed as CNF

// Virtual machines' properties used in atomic group expr, e.g. group = Gryffindor, tag = "backend"
// Used by NSX: Tag, Segment, (VM) Name, OS_Name, Computer_Name
// vmProperty implemented by collector.Segment, endpoints.vm, synthesis.Tag
// todo: Support OSName and ComputerName at POC?
type vmProperty interface {
	Name() string
}

// atomicTerm represent a simple condition, atom of defining a group:
// group/tag/segment/name(/computer_Name/OS_Name?) equal/not equal string
// formally, atomicTerm -> property equal const_string, not atomicTerm
type atomicTerm struct {
	property vmProperty
	toVal    string
	neg      bool
}

// tautology represents a condition that always holds.
// To be used as src or dst for cases where only dst or only src is restricted
type tautology struct {
}

// atomic interface for atomic expression - implemented by atomicTerm and tautology
type atomic interface {
	name() string   // name of group/tag/...
	string() string // full expression e.g. "group = slytherin"
	negate() atomic
	isNegation() bool
	isTautology() bool
	isNegateOf(atomic) bool
	disjoint(atomic, *Hints) bool   // based on hints
	supersetOf(atomic, *Hints) bool // based on hints
}

// Conjunction a DNF Conjunction of Atomics
type Conjunction []atomic

// SymbolicPath all path from a Src VM satisfying Src to Dst VM satisfying Dst
type SymbolicPath struct {
	Src  Conjunction
	Dst  Conjunction
	Conn *netset.TransportSet
}

type SymbolicPaths []*SymbolicPath

// Atomics map from Atomics string to *atomicTerm
// todo: to use for cashing
type Atomics map[string]atomic

type Hints struct {
	GroupsDisjoint [][]string
}
