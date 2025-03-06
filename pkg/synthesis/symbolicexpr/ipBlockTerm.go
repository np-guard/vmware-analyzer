package symbolicexpr

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func NewIPBlockTermTerm(ipBlock *topology.IPBlock) *ipBlockAtomicTerm {
	return &ipBlockAtomicTerm{atomicTerm: atomicTerm{}, IPBlock: ipBlock}
}

// OrigIP is non-empty for an ipTerm that is in its original rule form, or a negation of such ipTerm
// once we have more than one ipTerm in a Conjunction we merge; and then the OrigIP component is lost

func (ipBlockTerm *ipBlockAtomicTerm) String() string {
	var ipStr string
	if ipBlockTerm.Block.IsEmpty() {
		ipStr = "the empty block"
	} else {
		ipStr = ipBlockTerm.Block.String()
	}
	// prefer the OrigIP if exists
	origIP := ipBlockTerm.IPBlock.OriginalIP
	if origIP != "" {
		ipStr = origIP
	}
	op := " in "
	if ipBlockTerm.neg {
		op = " not in "
	}
	return "IP addr" + op + ipStr
}

// IsTautology an atomicTerm is a non-empty cond on a group, a tag etc and is thus not a tautology
func (ipBlockTerm *ipBlockAtomicTerm) IsTautology() bool {
	return complementary(ipBlockTerm.getBlock()).IsEmpty()
}

func (ipBlockTerm *ipBlockAtomicTerm) IsContradiction() bool {
	block := ipBlockTerm.getBlock()
	return block.IsEmpty()
}

func (ipBlockTerm *ipBlockAtomicTerm) name() string {
	return ipBlockTerm.String()
}

func (ipBlockTerm *ipBlockAtomicTerm) AsSelector() (string, bool) {
	return "to implement", false
}

// todo: move to netset??
func complementary(block *netset.IPBlock) *netset.IPBlock {
	allIPBlock := netset.GetCidrAll()
	return allIPBlock.Subtract(block)
}

func (ipBlockTerm *ipBlockAtomicTerm) getBlock() *netset.IPBlock {
	block := ipBlockTerm.Block
	if ipBlockTerm.isNegation() {
		block = complementary(block)
	}
	return block
}

// negate an ipBlockAtomicTerm; if it has the OrigIP component then uses neg; otherwise complement the IP block
func (ipBlockTerm *ipBlockAtomicTerm) negate() atomic {
	if ipBlockTerm.OriginalIP != "" { // orig block from rule
		return &ipBlockAtomicTerm{IPBlock: &topology.IPBlock{Block: ipBlockTerm.Block, OriginalIP: ipBlockTerm.OriginalIP},
			atomicTerm: atomicTerm{neg: !ipBlockTerm.neg}}
	}
	// block not kept in the form of original rule form
	return &ipBlockAtomicTerm{IPBlock: &topology.IPBlock{Block: complementary(ipBlockTerm.Block), OriginalIP: ""},
		atomicTerm: atomicTerm{}}
}

// returns true iff otherAt is negation of tagTerm; either syntactically or semantically
func (ipBlockTerm *ipBlockAtomicTerm) isNegateOf(otherAtom atomic) bool {
	otherBlock := otherAtom.getBlock()
	if otherBlock == nil {
		return false
	}
	return ipBlockTerm.getBlock().Equal(complementary(otherBlock))
}

// returns true iff ipBlocks otherAt and otherAtom are disjoint
func (ipBlockTerm *ipBlockAtomicTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	block := ipBlockTerm.getBlock()
	otherBlock := otherAtom.getBlock()
	if otherAtom == nil {
		return true // otherAtom is not an IPBlock
	}
	return !block.Overlap(otherBlock)
}

// returns true iff ipBlock tagTerm is superset of ipBlock otherAtom as given by hints
func (ipBlockTerm *ipBlockAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	if otherAtom.getBlock() == nil {
		return false
	}
	return ipBlockTerm.negate().disjoint(otherAtom, hints)
}

// Evaluates group and translates it into []*Conjunction
// If group has no expr or evaluation expr fails then uses the group names in  Conjunction
func getConjunctionForIPBlock(ipBlocks []*topology.RuleIPBlock) []*Conjunction {
	res := make([]*Conjunction, len(ipBlocks))
	for i, ipBlock := range ipBlocks {
		res[i] = &Conjunction{&ipBlockAtomicTerm{atomicTerm: atomicTerm{}, IPBlock: &ipBlock.IPBlock}}
	}
	return res
}
