package symbolicexpr

import "github.com/np-guard/models/pkg/netset"

func NewIPBlockTermTerm(ipBlock *ipBlock) *ipBlockAtomicTerm {
	return &ipBlockAtomicTerm{atomicTerm: atomicTerm{}, ipBlock: ipBlock}
}

// OrigIP is non-empty for an ipTerm that is in its original rule form, or a negation of such ipTerm
// once we have more than one ipTerm in a Conjunction we merge; and then the OrigIP component is lost

func (ipBlockTerm ipBlockAtomicTerm) String() string {
	ipStr := ipBlockTerm.Block.String()
	// prefer the OrigIP if exists
	if ipBlockTerm.ipBlock.OrigIP != "" {
		ipStr = ipBlockTerm.ipBlock.OrigIP
	}
	op := " in "
	if ipBlockTerm.neg {
		op = " not in "
	}
	return "IP block" + op + ipStr
}

func (ipBlockTerm ipBlockAtomicTerm) name() string {
	return ipBlockTerm.String()
}

func (ipBlockTerm ipBlockAtomicTerm) AsSelector() (string, bool) {
	return "to implement", false
}

// todo: move to netset??
func complementary(block *netset.IPBlock) *netset.IPBlock {
	allIPBlock, _ := netset.IPBlockFromCidr("0.0.0.0/0")
	return allIPBlock.Subtract(block)
}

func (ipBlockTerm ipBlockAtomicTerm) getBlock() *netset.IPBlock {
	block := ipBlockTerm.Block
	if ipBlockTerm.isNegation() {
		block = complementary(block)
	}
	return block
}

// negate an ipBlockAtomicTerm; if it has the OrigIP component then uses neg; otherwise complement the IP block
func (ipBlockTerm ipBlockAtomicTerm) negate() atomic {
	if ipBlockTerm.OrigIP != "" { // orig block from rule
		return ipBlockAtomicTerm{ipBlock: &ipBlock{Block: ipBlockTerm.Block, OrigIP: ipBlockTerm.OrigIP},
			atomicTerm: atomicTerm{neg: !ipBlockTerm.neg}}
	}
	// block not kept in the form of original rule form
	return ipBlockAtomicTerm{ipBlock: &ipBlock{Block: complementary(ipBlockTerm.Block), OrigIP: ""},
		atomicTerm: atomicTerm{}}
}

// returns true iff otherAt is negation of tagTerm; either syntactically or semantically
func (ipBlockTerm ipBlockAtomicTerm) isNegateOf(otherAtom atomic) bool {
	if isNegateOf(ipBlockTerm, otherAtom) {
		return true
	}
	otherIPBlock, ok := otherAtom.(ipBlockAtomicTerm)
	if !ok {
		return false
	}
	return ipBlockTerm.Block.Equal(complementary(otherIPBlock.Block))
}

// returns true iff ipBlocks otherAt and otherAtom are disjoint
func (ipBlockTerm ipBlockAtomicTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	otherIPBlock, ok := otherAtom.(ipBlockAtomicTerm)
	if !ok {
		return true
	}
	otherBlock := otherIPBlock.Block
	if otherIPBlock.neg {
		otherBlock = complementary(otherBlock)
	}
	return !ipBlockTerm.Block.Overlap(otherBlock)
}

// returns true iff ipBlock tagTerm is superset of ipBlock otherAtom as given by hints
func (ipBlockTerm ipBlockAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	otherIPBlock, ok := otherAtom.(ipBlockAtomicTerm)
	if !ok {
		return false
	}
	block := ipBlockTerm.getBlock()
	otherBlock := otherIPBlock.getBlock()
	return otherBlock.IsSubset(block)
}
