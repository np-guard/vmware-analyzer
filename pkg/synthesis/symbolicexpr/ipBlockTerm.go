package symbolicexpr

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func NewIPBlockTermTerm(ipBlock *topology.IpBlock) *ipBlockAtomicTerm {
	return &ipBlockAtomicTerm{atomicTerm: atomicTerm{}, IpBlock: ipBlock}
}

// OrigIP is non-empty for an ipTerm that is in its original rule form, or a negation of such ipTerm
// once we have more than one ipTerm in a Conjunction we merge; and then the OrigIP component is lost

func (ipBlockTerm ipBlockAtomicTerm) String() string {
	ipStr := ipBlockTerm.Block.String()
	// prefer the OrigIP if exists
	origIP := ipBlockTerm.IpBlock.OriginalIP
	if origIP != "" {
		ipStr = origIP
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

func getBlock(atom atomic) *netset.IPBlock {
	ipBlockTerm, ok := atom.(ipBlockAtomicTerm)
	if !ok {
		return nil
	}
	block := ipBlockTerm.Block
	if ipBlockTerm.isNegation() {
		block = complementary(block)
	}
	return block
}

// negate an ipBlockAtomicTerm; if it has the OrigIP component then uses neg; otherwise complement the IP block
func (ipBlockTerm ipBlockAtomicTerm) negate() atomic {
	if ipBlockTerm.OriginalIP != "" { // orig block from rule
		return ipBlockAtomicTerm{IpBlock: &topology.IpBlock{Block: ipBlockTerm.Block, OriginalIP: ipBlockTerm.OriginalIP},
			atomicTerm: atomicTerm{neg: !ipBlockTerm.neg}}
	}
	// block not kept in the form of original rule form
	return ipBlockAtomicTerm{IpBlock: &topology.IpBlock{Block: complementary(ipBlockTerm.Block), OriginalIP: ""},
		atomicTerm: atomicTerm{}}
}

// returns true iff otherAt is negation of tagTerm; either syntactically or semantically
func (ipBlockTerm ipBlockAtomicTerm) isNegateOf(otherAtom atomic) bool {
	thisBlock := getBlock(ipBlockTerm)
	otherBlock := getBlock(otherAtom)
	if otherBlock == nil {
		return false
	}
	return thisBlock.Equal(complementary(otherBlock))
}

// returns true iff ipBlocks otherAt and otherAtom are disjoint
func (ipBlockTerm ipBlockAtomicTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	block := getBlock(ipBlockTerm)
	otherBlock := getBlock(otherAtom)
	if otherAtom == nil {
		return true // otherAtom is not an IPBlock
	}
	return !block.Overlap(otherBlock)
}

// returns true iff ipBlock tagTerm is superset of ipBlock otherAtom as given by hints
func (ipBlockTerm ipBlockAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	block := getBlock(ipBlockTerm)
	otherBlock := getBlock(otherAtom)
	if otherBlock == nil { // otherAtom not IP block
		return false
	}
	return otherBlock.IsSubset(block)
}

// IsTautology an atomicTerm is a non empty cond on a group, a tag etc and is thus not a tautology
func (ipBlockTerm ipBlockAtomicTerm) IsTautology() bool {
	return complementary(ipBlockTerm.Block).IsEmpty()
}
