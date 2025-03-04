package symbolicexpr

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
	if c.contains(atom) {
		return c
	}
	// if c is an IPBlock, adds it to other IPBlock in the Conjunction, if any. Otherwise, just appends it
	// in the former case we lose the OriginalIP
	block := getBlock(atom)
	if block != nil { // atom is an IPBlock
		// looks for an  IPBlock in c
		for i, itemAtom := range *c {
			itemBlock := getBlock(itemAtom)
			if itemBlock == nil { // itemAtom not an IPBlock
				continue
			}
			// note that there could be at most one IPBlock in a conjunction, by design
			newIPBlockAtomicTerm := &ipBlockAtomicTerm{atomicTerm: atomicTerm{},
				IpBlock: &topology.IpBlock{Block: block.Intersect(itemBlock)}}
			(*c)[i] = newIPBlockAtomicTerm // overriding the IPBlock
			return c
		}
	}
	res := append(*c, atom)
	return &res
}

func (c *Conjunction) copy() *Conjunction {
	newC := Conjunction{}
	newC = append(newC, *c...)
	return &newC
}

// tautology: ipBlock 0.0.0.0/0 or tautology struct; at most 2 items
func (c *Conjunction) isTautology() bool {
	if len(*c) > 2 || len(*c) == 0 || !(*c)[0].IsTautology() {
		return false
	}
	if len(*c) == 1 || (len(*c) == 2 && (*c)[1].IsTautology()) {
		return true
	}
	return false
}

// remove redundant terms: tautology or redundant as per hints; the latter is when e.g., a and b are disjoint
// then "a and not b" - b is redundant
func (c *Conjunction) removeRedundant(hints *Hints) Conjunction {
	if len(*c) <= 1 {
		return *c
	}
	newC := Conjunction{}
	redundantRemoved := false
	for _, atom := range *c {
		if !atom.IsTautology() && !atomRedundantInConj(atom, c, hints) {
			newC = append(newC, atom)
		} else {
			redundantRemoved = true
		}
	}
	if len(newC) == 0 && redundantRemoved {
		return Conjunction{tautology{}}
	}
	return newC
}

// atomic atom is a redundant in Conjunction c, if it is a superset of one of c's terms; this applies to tagTerm and
// groupTerm; as to ipBlockTerm - there is at most one such term which is not redundant
func atomRedundantInConj(atom atomic, c *Conjunction, hints *Hints) bool {
	if len(*c) == 0 { // nil Conjunction is equiv to tautology
		return false
	}
	for _, otherAtom := range *c {
		if atom.supersetOf(otherAtom, hints) {
			return true
		}
	}
	return false
}

// checks whether the conjunction is empty: either syntactically, or contains an groupAtomicTerm and its negation
// or contains two atoms that are disjoint to each other by hints
func (c *Conjunction) isEmptySet(hints *Hints) bool {
	if len(*c) == 0 {
		return true
	}
	for i, outAtomicTerm := range *c {
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
	if len(*c) == 0 || len(*other) == 0 {
		return false
	}
	if other.isTautology() || c.isTautology() {
		return false
	}
	for _, atomicTerm := range *other {
		if c.contains(atomicTerm.negate()) || c.contradicts(atomicTerm, hints) {
			return true
		}
	}
	return false
}

func (c *Conjunction) contains(atom atomic) bool {
	atomBlock := getBlock(atom)
	for _, atomicItem := range *c {
		if atomBlock != nil { // atom is an IPBlock
			atomicItemBlock := getBlock(atomicItem)
			if atomicItem != nil {
				// by design there is at most one ipBlockTerm in Conjunction c
				return atomBlock.IsSubset(atomicItemBlock)
			}
		} else {
			if atomicItem.String() == (atom).String() {
				return true
			}
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
// c is tautology
func (c *Conjunction) isSuperset(other *Conjunction, hints *Hints) bool {
	if c.isTautology() || len(*c) == 0 { // tautology superset of everything;  nil Conjunction is equiv to tautology
		return true
	}
	if other.isTautology() { // tautology is a subset only of tautology
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
// e.g., given that Slytherin and Hufflepuff are disjoint, group != Hufflepuff is a superset of group = Slytherin
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
