package symbolicexpr

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	resources "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// the package implements a symbolic expression of enabled paths from symbolic src to symbolic dst, expressed as CNF

type atomicTerm struct {
	neg bool // equal to group/tag/... (false) or not-equal to it (true)
}

// groupAtomicTerm represent an equal/not-equal condition over a group
// todo: similar structs for /tag/(segment/vm_name/computer_Name/OS_Name?)
type groupAtomicTerm struct {
	atomicTerm
	group *collector.Group
}

type tagAtomicTerm struct {
	atomicTerm
	tag *resources.Tag
}

type ipBlockAtomicTerm struct {
	atomicTerm
	*topology.IPBlock
}

// tautology represents a condition that always holds.
// To be used as src or dst for cases where only dst or only src is restricted
type tautology struct {
}

// contradiction represents a condition that never holds; the negation of tautology
type contradiction struct {
}

// atomic interface for atomic expression - implemented by groupAtomicTerm, tagAtomicTerm, ipBlockAtomic,
// tautology and contradiction
type atomic interface {
	name() string                   // name of group/tag/...
	String() string                 // full expression e.g. "group = slytherin"
	negate() atomic                 // negation of the atomic term todo: once tag scope is supported will return []atomic
	isNegation() bool               // is term not-equal
	IsTautology() bool              // is term tautology?
	IsContradiction() bool          // is term tautology?
	isNegateOf(atomic) bool         // is the term negation of the other given term
	AsSelector() (string, bool)     // for the usage of policy synthesis
	disjoint(atomic, *Hints) bool   // based on hints
	supersetOf(atomic, *Hints) bool // super set of resources satisfying atom, given Hints based on hints
	GetBlock() *netset.IPBlock      // gets block for ipBlockTerm; nil otherwise
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

// Atomics map from Atomics string to *groupAtomicTerm
// todo: to use for cashing
type Atomics map[string]atomic

type Hints struct {
	GroupsDisjoint [][]string
}
