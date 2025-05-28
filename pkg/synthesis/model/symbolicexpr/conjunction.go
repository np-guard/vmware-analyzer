package symbolicexpr

// conjunction presents a conjunctions of terms

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

const emptySet = "empty set "

func (c *Term) String() string {
	if len(*c) == 0 {
		return emptySet
	}
	return "(" + common.JoinStringifiedSlice(*c, " and ") + ")"
}

func (c *Term) add(atom atomic) *Term {
	// tautology is the only term that refers to both internals and externals; thus treated differently and added unless
	// already exists
	if c.contains(atom) && !atom.IsTautology() || (atom.IsTautology() && c.hasTautology()) {
		return c
	}
	var ipBlockAddedToExisting bool
	// if c is an IPBlock, adds it to other IPBlock in the Term, if any. Otherwise, just appends it
	// in the former case we lose the OriginalIP
	block := atom.GetExternalBlock()
	var res Term
	// since tautology refers to both external and internal it should not be mixed with externals overriding the internals
	if block != nil && !atom.IsTautology() && c.hasExternalIPBlockTerm() { // atom is an IPBlockTerm
		// looks for an  IPBlock in c
		for _, itemAtom := range *c {
			itemBlock := itemAtom.GetExternalBlock()
			if itemBlock == nil || itemAtom.IsTautology() { // itemAtom not an external IP Term
				res = append(res, itemAtom)
			} else {
				// note that there could be at most one IPBlock in a conjunction, by design
				// since the Term's items are added, we should intersect the IPBlocks
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

func (c *Term) hasTautology() bool {
	for _, item := range *c {
		if item.IsTautology() {
			return true
		}
	}
	return false
}

func (c *Term) copy() *Term {
	newC := Term{}
	newC = append(newC, *c...)
	return &newC
}

// tautology: ipBlock 0.0.0.0/0, allGroups: all internal resources
func (c *Term) isTautology() bool {
	if len(*c) == 1 && (*c)[0].IsTautology() {
		return true
	}
	return false
}

// allGroups: all internal resources
func (c *Term) isAllGroup() bool {
	if len(*c) == 1 && (*c)[0].IsAllGroups() {
		return true
	}
	return false
}

// tautology: ipBlock 0.0.0.0/0, allGroups: all internal resources
func (c *Term) isTautologyOrAllGroups() bool {
	return c.isTautology() || c.isAllGroup()
}

// remove redundant terms: allGroups or redundant as per hints; the latter is when e.g., a and b are disjoint
// then "a and not b" - b is redundant
// relevant only to Conjunctions referring to internal resources
func (c *Term) removeRedundant(hints *Hints) Term {
	if len(*c) <= 1 || c.hasExternalIPBlockTerm() {
		return *c
	}
	newC := Term{}
	redundantRemoved := false
	for _, atom := range *c {
		// tautology is both external and internal, thus the "superset" redundancy does not apply to it
		if atom.IsTautology() || (!atom.IsAllGroups() && !atomRedundantInConj(atom, c, hints)) {
			newC = append(newC, atom)
		} else {
			redundantRemoved = true
		}
	}
	if len(newC) == 0 && redundantRemoved {
		return Term{allGroup{}}
	}
	return newC
}

// atomic atom is a redundant in Term c, if it is a superset of one of c's terms; this applies to tagTerm and
// groupTerm; as to ipBlockTerm - there is at most one such term which is not redundant by design
func atomRedundantInConj(atom atomic, c *Term, hints *Hints) bool {
	if len(*c) == 0 { // nil Term is equiv to tautology
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

func (c *Term) hasExternalIPBlockTerm() bool {
	for _, term := range *c {
		if term.IsTautology() { // tautology is both external and internal
			continue
		}
		if term.IsAllExternal() {
			return true
		}
		if term.GetExternalBlock() != nil {
			return true
		}
	}
	return false
}

func (c *Term) hasTagOrGroupOrInternalIPTerm() bool {
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
func (c *Term) isEmpty(hints *Hints) bool {
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
func (c *Term) disjoint(other *Term, hints *Hints) bool {
	// empty sets are disjoint to anything
	if c.isEmpty(hints) || other.isEmpty(hints) {
		return true
	}
	// empty Term equiv to tautology; tautology not disjoint to any non-empty set
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

func (c *Term) areConjunctionNotSameType(other *Term) bool {
	return c.hasTagOrGroupOrInternalIPTerm() && other.hasExternalIPBlockTerm() ||
		(other.hasTagOrGroupOrInternalIPTerm() && c.hasExternalIPBlockTerm())
}

// a Term c contains an atom atomic if:
// semantically: the condition in atom is already implied by c
// syntactically:
// if atom is a tagTerm or a groupTerm, then if the Term c contains the atom literally
// if atom is an IPBlock, if there is already an IPBlock in c that atom is a superset of it.
func (c *Term) contains(atom atomic) bool {
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

func (c *Term) contradicts(atom atomic, hints *Hints) bool {
	for _, atomicTerm := range *c {
		if atomicTerm.disjoint(atom, hints) {
			return true
		}
	}
	return false
}

// Term c is superset of other if either:
// any resource satisfying other also satisfies c,
// this is the case if any term in c either exists in other or is a subset of it, or
// both Conjunctions refer to external IPs/internal resources and c is tautology or allGroups
// (recall that a non-empty Term can either refer to internal resources or to external IPs)
func (c *Term) isSuperset(other *Term, hints *Hints) bool {
	if c.isTautology() || len(*c) == 0 { // tautology superset of anything;  nil Term is equiv to tautology
		return true
	}
	if c.areConjunctionNotSameType(other) {
		return false
	}
	if other.isTautology() { // c is not tautology, then can't be superset of tautology
		return false
	}
	// got here: both conjunctions refer to external ips or both refer to internal resources, c and other both not tautology

	// tautology/allGroups superset of everything which is internal
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

// Term c is a superset of atomic atom if any resource satisfying atom also satisfies c
// this is the case if each of c's term is a superset of atom
// e.g.,  1.2.1.0/8 is a superset of 1.2.1.0/16;
// given that Slytherin and Hufflepuff are disjoint, group != Hufflepuff is a superset of group = Slytherin
func conjSupersetOfAtom(c *Term, atom atomic, hints *Hints) bool {
	if len(*c) == 0 { // nil Term is equiv to tautology
		return false
	}
	for _, otherAtom := range *c {
		if !otherAtom.supersetOf(atom, hints) {
			return false
		}
	}
	return true
}

// if the Term has a tautology and also other terms, then it should be processed:
// this is since the Term (excluding the tautology) has externals *or* internals while tautology refers to
// and as a result the Term is a mess
// if the Term has externals (in addition to the tautology) then it should be replaced with two Conjunctions:
// 1. *All Groups Term* (equiv to all internals)
// 2. The externals in the original Term (excluding the tautology)
// if the Term has internals (in addition to the tautology) then it should be replaced with two Conjunctions:
// 1. *All Externals Term*
// 2. The internals in the original Term (excluding the tautology)
func (c *Term) processTautology(externalRelevant bool) []*Term {
	resOrig := []*Term{c}
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
	if tautIndex == -1 { // no tautology in Term? nothing to do here
		return resOrig
	}
	var atomicsWOTautology []atomic
	atomicsWOTautology = append(atomicsWOTautology, (*c)[:tautIndex]...)
	atomicsWOTautology = append(atomicsWOTautology, (*c)[tautIndex+1:]...)
	var conjWOTautology Term = atomicsWOTautology
	// by design (in ComputeAllowGivenDenies()), in addition to the tautology, we either have externals *xor* internals
	if c.hasExternalIPBlockTerm() {
		// Term of tautology and externals. Divided to two Conjunctions: one of *allGroup* and the non-tautology externals
		var allGroupConj = Term{allGroup{}}
		return []*Term{&conjWOTautology, &allGroupConj}
	}
	// Term of tautology and internals. Divided to two Conjunctions: one of *allExternal* and the non-tautology externals
	if !externalRelevant {
		return []*Term{&conjWOTautology}
	}
	var allExtrenalConj = Term{allExternal{}}
	return []*Term{&conjWOTautology, &allExtrenalConj}
}

// hasOnlyIPBlockTerms returns true if all terms in Term c are based on IPBlocks
func (c *Term) hasOnlyIPBlockTerms() bool {
	for _, item := range *c {
		if item.GetExternalBlock() == nil && item.getInternalBlock() == nil {
			return false
		}
	}
	return true
}

func ConjunctionsOnlyIPBlockTerms(conjunctions []*Term) bool {
	for _, conj := range conjunctions {
		if !conj.hasOnlyIPBlockTerms() {
			return false
		}
	}
	return true
}
