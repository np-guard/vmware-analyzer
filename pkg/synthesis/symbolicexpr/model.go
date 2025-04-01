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

// abstraction of all terms representing group based internal resources: groupAtomicTerm and tagAtomicTerm
type groupBasedInternalResource struct {
	anyInternalResource
}

// abstraction of all terms representing internal resources: groupBasedInternalResource and internalIPTerm
type anyInternalResource struct {
}

// groupAtomicTerm represent an equal/not-equal condition over a group
type groupAtomicTerm struct {
	groupBasedInternalResource
	atomicTerm
	group *collector.Group
}

type tagAtomicTerm struct {
	groupBasedInternalResource
	atomicTerm
	tag *resources.Tag
}

// internalIPTerm represents an VMs originating from an NSX internal cidr which is not composed of segments
// We keep the original IP block, but we do not merge/subtract (as in the case of external IP blocks)
// We do derive disjointness/supersetness w.r.t. other internal blocks (in addition to hints)
type internalIPTerm struct {
	anyInternalResource
	atomicTerm
	ruleBlock *topology.RuleIPBlock
}

type SegmentTerm struct {
	anyInternalResource
	atomicTerm
	segment *topology.Segment
}

type externalIPTerm struct {
	atomicTerm
	*topology.IPBlock
}

// tautology represents 0.0.0.0/0
type tautology struct {
}

// contradiction represents a condition that never holds; the negation of tautology
type contradiction struct {
}

// allGroups: represents all internal resources (e.g. VMs)
type allGroup struct {
}

// noGroups: negation of allGroup
type noGroup struct {
}

// atomic interface for atomic expression - implemented by groupAtomicTerm, tagAtomicTerm, ipBlockAtomic,
// tautology and contradiction
type atomic interface {
	name() string                      // name of group/tag/...
	String() string                    // full expression e.g. "group = slytherin"
	negate() atomic                    // negation of the atomic term todo: once tag scope is supported will return []atomic
	isNegation() bool                  // is term negation
	IsTautology() bool                 // is term tautology (0.0.0.0/0)?
	IsContradiction() bool             // is term contradiction (negation of tautology)?
	IsAllGroups() bool                 // term is true for any internal resource (allGroup, tautology)?
	IsNoGroup() bool                   // term is false for any internal resource (noGroup, contradiction)?
	isNegateOf(atomic) bool            // is the term negation of the other given term
	AsSelector() (string, bool)        // for the usage of policy synthesis
	disjoint(atomic, *Hints) bool      // based on hints
	supersetOf(atomic, *Hints) bool    // super set of resources satisfying atom, given Hints based on hints
	GetExternalBlock() *netset.IPBlock // gets block for ipBlockTerm; nil otherwise
	getInternalBlock() *netset.IPBlock // gets block for internalIPTerm; nil otherwise
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
