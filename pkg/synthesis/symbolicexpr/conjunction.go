package symbolicexpr

// conjunction presents a conjunctions of terms

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

const emptySet = "empty set "

func (c *Conjunction) String() string {
	if len(*c) == 0 {
		return emptySet
	}
	return "(" + common.JoinStringifiedSlice(*c, " and ") + ")"
}

func (c *Conjunction) add(atom atomic) *Conjunction {
	// tautology is the only term that refers to both internals and externals; thus treated differently and added unless
	// already exists
	if c.contains(atom) && !atom.IsTautology() || (atom.IsTautology() && c.hasTautology()) {
		return c
	}
	var ipBlockAddedToExisting bool
	// if c is an IPBlock, adds it to other IPBlock in the Conjunction, if any. Otherwise, just appends it
	// in the former case we lose the OriginalIP
	block := atom.GetExternalBlock()
	var res Conjunction
	// since tautology refers to both external and internal it should not be mixed with externals overriding the internals
	if block != nil && !atom.IsTautology() { // atom is an IPBlockTerm
		// looks for an  IPBlock in c
		for _, itemAtom := range *c {
			itemBlock := itemAtom.GetExternalBlock()
			if itemBlock == nil { // itemAtom not an IPBlock
				res = append(res, itemAtom)
			} else {
				// note that there could be at most one IPBlock in a conjunction, by design
				// since the Conjunction's items are added, we should intersect the IPBlocks
				newIPBlockAtomicTerm := &externalIPTerm{atomicTerm: atomicTerm{},
					IPBlock: &topology.IPBlock{Block: block.Intersect(itemBlock)}}
				res = append(res, newIPBlockAtomicTerm)
				ipBlockAddedToExisting = true
			}
		}
	}
	if ipBlockAddedToExisting {
		return &res
	}
	// atom was not an ipBlockTerm or c did not yet have an ipBlockTerm
	res = append(*c, atom)

	return &res
}

func (c *Conjunction) hasTautology() bool {
	for _, item := range *c {
		if item.IsTautology() {
			return true
		}
	}
	return false
}

func (c *Conjunction) copy() *Conjunction {
	newC := Conjunction{}
	newC = append(newC, *c...)
	return &newC
}

// tautology: ipBlock 0.0.0.0/0, allGroups: all internal resources
func (c *Conjunction) isTautology() bool {
	if len(*c) == 1 && (*c)[0].IsTautology() {
		return true
	}
	return false
}

// allGroups: all internal resources
func (c *Conjunction) isAllGroup() bool {
	if len(*c) == 1 && (*c)[0].IsAllGroups() {
		return true
	}
	return false
}

// tautology: ipBlock 0.0.0.0/0, allGroups: all internal resources
func (c *Conjunction) isTautologyOrAllGroups() bool {
	return c.isTautology() || c.isAllGroup()
}

// remove redundant terms: allGroups or redundant as per hints; the latter is when e.g., a and b are disjoint
// then "a and not b" - b is redundant
// relevant only to Conjunctions referring to internal resources
func (c *Conjunction) removeRedundant(hints *Hints) Conjunction {
	if len(*c) <= 1 || c.hasExternalIPBlockTerm() {
		return *c
	}
	newC := Conjunction{}
	redundantRemoved := false
	for _, atom := range *c {
		if !atom.IsAllGroups() && !atomRedundantInConj(atom, c, hints) {
			newC = append(newC, atom)
		} else {
			redundantRemoved = true
		}
	}
	if len(newC) == 0 && redundantRemoved {
		return Conjunction{allGroup{}}
	}
	return newC
}

// atomic atom is a redundant in Conjunction c, if it is a superset of one of c's terms; this applies to tagTerm and
// groupTerm; as to ipBlockTerm - there is at most one such term which is not redundant by design
func atomRedundantInConj(atom atomic, c *Conjunction, hints *Hints) bool {
	if len(*c) == 0 { // nil Conjunction is equiv to tautology
		return false
	}
	for _, otherAtom := range *c {
		if atom.String() == otherAtom.String() {
			continue
		}
		if atom.supersetOf(otherAtom, hints) {
			return true
		}
	}
	return false
}

func (c *Conjunction) hasExternalIPBlockTerm() bool {
	for _, term := range *c {
		if term.IsTautology() {
			return true
		}
		if term.GetExternalBlock() != nil {
			return true
		}
	}
	return false
}

func (c *Conjunction) hasTagOrGroupOrInternalIPTerm() bool {
	for _, term := range *c {
		if term.isInternalOnly() {
			return true
		}
	}
	return false
}

// isEmpty: checks whether the conjunction is false:
// either contains an ipBlockTerm and a tagTerm/groupTerm (ipBlockTerm presents only external ips)
// or contains an empty ipBlockTerm
// or contains groupAtomicTerm and its negation
// or contains two atoms that are disjoint to each other by hints
func (c *Conjunction) isEmpty(hints *Hints) bool {
	if len(*c) == 0 {
		return false
	}
	if c.hasTagOrGroupOrInternalIPTerm() && c.hasExternalIPBlockTerm() {
		return false
	}
	for i, outAtomicTerm := range *c {
		if outAtomicTerm.IsContradiction() {
			return true
		}
		if outAtomicTerm.GetExternalBlock() != nil {
			continue
		}
		reminder := *c
		reminder = reminder[i+1:]
		for _, inAtomicTerm := range reminder {
			if outAtomicTerm.isNegateOf(inAtomicTerm) || outAtomicTerm.disjoint(inAtomicTerm, hints) {
				return true
			}
		}
	}
	return false
}

// checks whether conjunction other is disjoint to conjunction c
// this is the case if there's a term in c and its contradiction in other
// or if there are two terms that are disjoint to each other by hints
func (c *Conjunction) disjoint(other *Conjunction, hints *Hints) bool {
	// empty sets are disjoint to anything
	if c.isEmpty(hints) || other.isEmpty(hints) {
		return true
	}
	// empty Conjunction equiv to tautology; tautology not disjoint to any non-empty set
	if len(*c) == 0 || len(*other) == 0 || c.isTautology() || other.isTautology() {
		return false
	}
	// external ips disjoint to internal resources
	if c.areConjunctionNotSameType(other) {
		return true
	}
	// both conjunctions refer to external ips or both refer to internal resources, and neither is tautology
	if c.isAllGroup() || other.isAllGroup() {
		return false
	}
	for _, atomicTerm := range *other {
		if c.contains(atomicTerm.negate()) || c.contradicts(atomicTerm, hints) {
			return true
		}
	}
	return false
}

func (c *Conjunction) areConjunctionNotSameType(other *Conjunction) bool {
	return c.hasTagOrGroupOrInternalIPTerm() && other.hasExternalIPBlockTerm() ||
		(other.hasTagOrGroupOrInternalIPTerm() && c.hasExternalIPBlockTerm())
}

// a Conjunction c contains an atom atomic if:
// semantically: the condition in atom is already implied by c
// syntactically:
// if atom is a tagTerm or a groupTerm, then if the Conjunction c contains the atom literally
// if atom is an IPBlock, if there is already an IPBlock in c that atom is a superset of it.
func (c *Conjunction) contains(atom atomic) bool {
	if atom.IsTautology() || (c.hasTagOrGroupOrInternalIPTerm() && atom.IsAllGroups()) {
		return true
	}
	for _, atomicItem := range *c {
		// the following is relevant only when both atom and atomicItem are ipBlockTerms;
		// in the other cases supersetOf is based on hints
		if atom.supersetOf(atomicItem, &Hints{}) {
			return true
		}
		if atomicItem.String() == (atom).String() {
			return true
		}
	}

	return false
}

func (c *Conjunction) contradicts(atom atomic, hints *Hints) bool {
	for _, atomicTerm := range *c {
		if atomicTerm.disjoint(atom, hints) {
			return true
		}
	}
	return false
}

// Conjunction c is superset of other if either:
// any resource satisfying other also satisfies c,
// this is the case if any term in c either exists in other or is a subset of it, or
// both Conjunctions refer to external IPs/internal resources and c is tautology or allGroups
// (recall that a non-empty Conjunction can either refer to internal resources or to external IPs)
func (c *Conjunction) isSuperset(other *Conjunction, hints *Hints) bool {
	if c.isTautology() || len(*c) == 0 { // tautology superset of anything;  nil Conjunction is equiv to tautology
		return true
	}
	if c.areConjunctionNotSameType(other) {
		return false
	}
	// got here: both conjunctions refer to external ips or both refer to internal resources, c not tautology

	// tautology/allGroups superset of everything
	if c.isAllGroup() {
		return true
	}
	if other.isTautologyOrAllGroups() { // tautology/allGroups is a subset only of tautology/allGroups
		return false
	}
	for _, atom := range *c {
		if !other.contains(atom) && !conjSupersetOfAtom(other, atom, hints) {
			return false
		}
	}
	return true
}

// Conjunction c is a superset of atomic atom if any resource satisfying atom also satisfies c
// this is the case if each of c's term is a superset of atom
// e.g.,  1.2.1.0/8 is a superset of 1.2.1.0/16;
// given that Slytherin and Hufflepuff are disjoint, group != Hufflepuff is a superset of group = Slytherin
func conjSupersetOfAtom(c *Conjunction, atom atomic, hints *Hints) bool {
	if len(*c) == 0 { // nil Conjunction is equiv to tautology
		return false
	}
	for _, otherAtom := range *c {
		if !otherAtom.supersetOf(atom, hints) {
			return false
		}
	}
	return true
}

// if the Conjunction has a tautology and also other terms, then it should be processed:
// this is since the Conjunction (excluding the tautology) has externals *or* internals while tautology refers to
// and as a result the Conjunction is a mess
// if the Conjunction has externals (in addition to the tautology) then it should be replaced with two Conjunctions:
// 1. *All Groups Term* (equiv to all internals)
// 2. The externals in the original Conjunction (excluding the tautology)
// if the Conjunction has internals (in addition to the tautology) then it should be replaced with two Conjunctions:
// 1. *All Externals Term*
// 2. The internals in the original Conjunction (excluding the tautology)
func (c *Conjunction) processTautology() []*Conjunction {
	resOrig := []*Conjunction{c}
	if len(*c) < 2 {
		return resOrig
	}
	tautIndex := -1
	for i, term := range *c {
		if term.IsTautology() {
			tautIndex = i
			break
		}
	}
	if tautIndex == -1 { // no tautology in Conjunction? nothing to do here
		return resOrig
	}
	// Conjunction of and externals. Divided to two Conjunctions: one of *allGroup* and the non-tautology externals
	var atomicsWOTautology []atomic
	atomicsWOTautology = append(atomicsWOTautology, (*c)[:tautIndex]...)
	atomicsWOTautology = append(atomicsWOTautology, (*c)[tautIndex+1:]...)
	var conjWOTautology Conjunction = atomicsWOTautology
	// we get here after removeRedundant; so, in addition to the tautology, we either have externals *xor* internals
	if c.hasExternalIPBlockTerm() {
		var allGroupConj = Conjunction{allGroup{}}
		return []*Conjunction{&conjWOTautology, &allGroupConj}
	}
	// c has internal terms (in addition to the tautology)
	var allExtrenalConj = Conjunction{allExternal{}}
	return []*Conjunction{&conjWOTautology, &allExtrenalConj}
}
