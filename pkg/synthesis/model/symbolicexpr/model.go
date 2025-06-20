package symbolicexpr

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// the package implements a symbolic expression of enabled paths from symbolic src to symbolic dst, expressed as CNF

type atomicTerm struct {
	neg bool // equal to group/tag/... (false) or not-equal to it (true)
}

// abstraction of all terms representing group based internal nsx: groupAtomicTerm and tagAtomicTerm
type groupBasedInternalResource struct {
	anyInternalResource
}

// abstraction of all terms representing internal nsx: groupBasedInternalResource and internalIPTerm
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
	tag *nsx.Tag
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

// allGroups: represents all internal nsx (e.g. VMs)
type allGroup struct {
}

// noGroups: negation of allGroup
type noGroup struct {
}

// allExternal: representative of *all* external IPs
type allExternal struct {
}

// Atomic interface for Atomic expression - implemented by groupAtomicTerm, tagAtomicTerm, ipBlockAtomic,
// tautology and contradiction
type Atomic interface {
	name() string                      // name of group/tag/...
	String() string                    // full expression e.g. "group = slytherin"
	negate() Atomic                    // negation of the atomic term todo: once tag scope is supported will return []atomic
	isNegation() bool                  // is term negation
	IsTautology() bool                 // is term tautology (0.0.0.0/0)?
	IsContradiction() bool             // is term contradiction (negation of tautology)?
	IsAllGroups() bool                 // term is true for any internal resource (allGroup, tautology)?
	IsNoGroup() bool                   // term is false for any internal resource (noGroup, contradiction)?
	IsSegment() bool                   // term is segmentTerm
	IsAllExternal() bool               // term is allExternal
	isNegateOf(Atomic) bool            // is the term negation of the other given term
	isInternalOnly() bool              // is the atom internal, not including tautology
	AsSelector() (string, bool)        // for the usage of policy synthesis
	disjoint(Atomic, *Hints) bool      // based on hints
	supersetOf(Atomic, *Hints) bool    // super set of nsx satisfying atom, given Hints based on hints
	GetExternalBlock() *netset.IPBlock // gets block for ipBlockTerm; nil otherwise
	getInternalBlock() *netset.IPBlock // gets block for internalIPTerm; nil otherwise
}

// Term - ANDing []atomic
type Term []Atomic

// DNF of []*Term; namely ORing the terms
type DNF []*Term

// SymbolicPath all path from a Src VM satisfying Src to Dst VM satisfying Dst
type SymbolicPath struct {
	Src  Term
	Dst  Term
	Conn *netset.TransportSet
}

// SymbolicPaths disjunction of SymbolicPaths
type SymbolicPaths []*SymbolicPath

type Hints struct {
	GroupsDisjoint [][]string
}
