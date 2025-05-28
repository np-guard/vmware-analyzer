package symbolicexpr

// term presents a conjunctions of atomics (or a single atomic)

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

const emptySet = "empty set "

func (t *Term) String() string {
	if len(*t) == 0 {
		return emptySet
	}
	return "(" + common.JoinStringifiedSlice(*t, " and ") + ")"
}

func (t *Term) add(atom atomic) *Term {
	// tautology is the only term that refers to both internals and externals; thus treated differently and added unless
	// already exists
	if t.contains(atom) && !atom.IsTautology() || (atom.IsTautology() && t.hasTautology()) {
		return t
	}
	var ipBlockAddedToExisting bool
	// if t is an IPBlock, adds it to other IPBlock in the Term, if any. Otherwise, just appends it
	// in the former case we lose the OriginalIP
	block := atom.GetExternalBlock()
	var res Term
	// since tautology refers to both external and internal it should not be mixed with externals overriding the internals
	if block != nil && !atom.IsTautology() && t.hasExternalIPBlockTerm() { // atom is an IPBlockTerm
		// looks for an  IPBlock in t
		for _, itemAtom := range *t {
			itemBlock := itemAtom.GetExternalBlock()
			if itemBlock == nil || itemAtom.IsTautology() { // itemAtom not an external IP Term
				res = append(res, itemAtom)
			} else {
				// note that there could be at most one IPBlock in a term, by design
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
	// atom was not an ipBlockTerm or t did not yet have an ipBlockTerm
	res = append(*t, atom)

	return &res
}

func (t *Term) hasTautology() bool {
	for _, item := range *t {
		if item.IsTautology() {
			return true
		}
	}
	return false
}

func (t *Term) copy() *Term {
	newC := Term{}
	newC = append(newC, *t...)
	return &newC
}

// tautology: ipBlock 0.0.0.0/0, allGroups: all internal resources
func (t *Term) isTautology() bool {
	if len(*t) == 1 && (*t)[0].IsTautology() {
		return true
	}
	return false
}

// allGroups: all internal resources
func (t *Term) isAllGroup() bool {
	if len(*t) == 1 && (*t)[0].IsAllGroups() {
		return true
	}
	return false
}

// tautology: ipBlock 0.0.0.0/0, allGroups: all internal resources
func (t *Term) isTautologyOrAllGroups() bool {
	return t.isTautology() || t.isAllGroup()
}

// remove redundant terms: allGroups or redundant as per hints; the latter is when e.g., a and b are disjoint
// then "a and not b" - b is redundant
// relevant only to terms referring to internal resources
func (t *Term) removeRedundant(hints *Hints) Term {
	if len(*t) <= 1 || t.hasExternalIPBlockTerm() {
		return *t
	}
	newC := Term{}
	redundantRemoved := false
	for _, atom := range *t {
		// tautology is both external and internal, thus the "superset" redundancy does not apply to it
		if atom.IsTautology() || (!atom.IsAllGroups() && !atomRedundantInTerm(atom, t, hints)) {
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
func atomRedundantInTerm(atom atomic, t *Term, hints *Hints) bool {
	if len(*t) == 0 { // nil Term is equiv to tautology
		return false
	}
	for _, otherAtom := range *t {
		if atom.String() == otherAtom.String() {
			continue
		}
		if atom.supersetOf(otherAtom, hints) {
			return true
		}
	}
	return false
}

func (t *Term) hasExternalIPBlockTerm() bool {
	for _, term := range *t {
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

func (t *Term) hasTagOrGroupOrInternalIPTerm() bool {
	for _, term := range *t {
		if term.isInternalOnly() {
			return true
		}
	}
	return false
}

// isEmpty: checks whether the term is false:
// either contains an ipBlockTerm and a tagTerm/groupTerm (ipBlockTerm presents only external ips)
// or contains an empty ipBlockTerm
// or contains groupAtomicTerm and its negation
// or contains two atoms that are disjoint to each other by hints
func (t *Term) isEmpty(hints *Hints) bool {
	if len(*t) == 0 {
		return false
	}
	if t.hasTagOrGroupOrInternalIPTerm() && t.hasExternalIPBlockTerm() {
		return false
	}
	for i, outAtomicTerm := range *t {
		if outAtomicTerm.IsContradiction() {
			return true
		}
		if outAtomicTerm.GetExternalBlock() != nil {
			continue
		}
		reminder := *t
		reminder = reminder[i+1:]
		for _, inAtomicTerm := range reminder {
			if outAtomicTerm.isNegateOf(inAtomicTerm) || outAtomicTerm.disjoint(inAtomicTerm, hints) {
				return true
			}
		}
	}
	return false
}

// checks whether term other is disjoint to term t
// this is the case if there's a term in c and its contradiction in other
// or if there are two terms that are disjoint to each other by hints
func (t *Term) disjoint(other *Term, hints *Hints) bool {
	// empty sets are disjoint to anything
	if t.isEmpty(hints) || other.isEmpty(hints) {
		return true
	}
	// empty Term equiv to tautology; tautology not disjoint to any non-empty set
	if len(*t) == 0 || len(*other) == 0 || t.isTautology() || other.isTautology() {
		return false
	}
	// external ips disjoint to internal resources
	if t.areTermsNotSameType(other) {
		return true
	}
	// both terms refer to external ips or both refer to internal resources, and neither is tautology
	if t.isAllGroup() || other.isAllGroup() {
		return false
	}
	for _, atomicTerm := range *other {
		if t.contains(atomicTerm.negate()) || t.contradicts(atomicTerm, hints) {
			return true
		}
	}
	return false
}

func (t *Term) areTermsNotSameType(other *Term) bool {
	return t.hasTagOrGroupOrInternalIPTerm() && other.hasExternalIPBlockTerm() ||
		(other.hasTagOrGroupOrInternalIPTerm() && t.hasExternalIPBlockTerm())
}

// a Term c contains an atom atomic if:
// semantically: the condition in atom is already implied by c
// syntactically:
// if atom is a tagTerm or a groupTerm, then if the Term c contains the atom literally
// if atom is an IPBlock, if there is already an IPBlock in c that atom is a superset of it.
func (t *Term) contains(atom atomic) bool {
	if atom.IsTautology() || (t.hasTagOrGroupOrInternalIPTerm() && atom.IsAllGroups()) {
		return true
	}
	for _, atomicItem := range *t {
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

func (t *Term) contradicts(atom atomic, hints *Hints) bool {
	for _, atomicTerm := range *t {
		if atomicTerm.disjoint(atom, hints) {
			return true
		}
	}
	return false
}

// Term c is superset of other if either:
// any resource satisfying other also satisfies c,
// this is the case if any term in c either exists in other or is a subset of it, or
// both terms refer to external IPs/internal resources and c is tautology or allGroups
// (recall that a non-empty Term can either refer to internal resources or to external IPs)
func (t *Term) isSuperset(other *Term, hints *Hints) bool {
	if t.isTautology() || len(*t) == 0 { // tautology superset of anything;  nil Term is equiv to tautology
		return true
	}
	if t.areTermsNotSameType(other) {
		return false
	}
	if other.isTautology() { // t is not tautology, then can't be superset of tautology
		return false
	}
	// got here: both terms refer to external ips or both refer to internal resources, t and other both not tautology

	// tautology/allGroups superset of everything which is internal
	if t.isAllGroup() {
		return true
	}
	if other.isTautologyOrAllGroups() { // tautology/allGroups is a subset only of tautology/allGroups
		return false
	}
	for _, atom := range *t {
		if !other.contains(atom) && !termSupersetOfAtom(other, atom, hints) {
			return false
		}
	}
	return true
}

// Term t is a superset of atomic atom if any resource satisfying atom also satisfies c
// this is the case if each of c's term is a superset of atom
// e.g.,  1.2.1.0/8 is a superset of 1.2.1.0/16;
// given that Slytherin and Hufflepuff are disjoint, group != Hufflepuff is a superset of group = Slytherin
func termSupersetOfAtom(t *Term, atom atomic, hints *Hints) bool {
	if len(*t) == 0 { // nil Term is equiv to tautology
		return false
	}
	for _, otherAtom := range *t {
		if !otherAtom.supersetOf(atom, hints) {
			return false
		}
	}
	return true
}

// if the Term has a tautology and also other terms, then it should be processed:
// this is since the Term (excluding the tautology) has externals *or* internals while tautology refers to
// and as a result the Term is a mess
// if the Term has externals (in addition to the tautology) then it should be replaced with two terms:
// 1. *All Groups Term* (equiv to all internals)
// 2. The externals in the original Term (excluding the tautology)
// if the Term has internals (in addition to the tautology) then it should be replaced with two terms:
// 1. *All Externals Term*
// 2. The internals in the original Term (excluding the tautology)
func (t *Term) processTautology(externalRelevant bool) DNF {
	resOrig := DNF{t}
	if len(*t) < 2 {
		return resOrig
	}
	tautIndex := -1
	for i, term := range *t {
		if term.IsTautology() {
			tautIndex = i
			break
		}
	}
	if tautIndex == -1 { // no tautology in Term? nothing to do here
		return resOrig
	}
	var atomicsWOTautology []atomic
	atomicsWOTautology = append(atomicsWOTautology, (*t)[:tautIndex]...)
	atomicsWOTautology = append(atomicsWOTautology, (*t)[tautIndex+1:]...)
	var termWOTautology Term = atomicsWOTautology
	// by design (in ComputeAllowGivenDenies()), in addition to the tautology, we either have externals *xor* internals
	if t.hasExternalIPBlockTerm() {
		// Term of tautology and externals. Divided to two terms: one of *allGroup* and the non-tautology externals
		var allGroupTerm = Term{allGroup{}}
		return DNF{&termWOTautology, &allGroupTerm}
	}
	// Term of tautology and internals. Divided to two Terms: one of *allExternal* and the non-tautology externals
	if !externalRelevant {
		return DNF{&termWOTautology}
	}
	var allExtrenalTerms = Term{allExternal{}}
	return DNF{&termWOTautology, &allExtrenalTerms}
}

// hasOnlyIPBlockTerms returns true if all terms in Term c are based on IPBlocks
func (t *Term) hasOnlyIPBlockTerms() bool {
	for _, item := range *t {
		if item.GetExternalBlock() == nil && item.getInternalBlock() == nil {
			return false
		}
	}
	return true
}

func TermsOnlyIPBlockTerms(dnf DNF) bool {
	for _, term := range dnf {
		if !term.hasOnlyIPBlockTerms() {
			return false
		}
	}
	return true
}
