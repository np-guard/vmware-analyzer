package symbolicexpr

// ipBlockTerm represents external IPs

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func NewIPBlockTerm(ipBlock *topology.IPBlock) *ipBlockAtomicTerm {
	// todo: dump if ipBlock has internal address
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

// following 2 functions are false and the last one true for ipBlock since ipBlock presents only external IPs

func (ipBlockTerm *ipBlockAtomicTerm) IsTautology() bool {
	return false
}

func (ipBlockTerm *ipBlockAtomicTerm) IsAllGroups() bool {
	return false
}

// IsNoGroup ipBlockAtomicTerm neq 0.0.0.0/0 presents external addresses, thus IsNoGroup is true
func (ipBlockTerm *ipBlockAtomicTerm) IsNoGroup() bool {
	return true
}

// IsContradiction true iff the ipBlock is empty
func (ipBlockTerm *ipBlockAtomicTerm) IsContradiction() bool {
	return ipBlockTerm.GetBlock().IsEmpty()
}

//

func (ipBlockTerm *ipBlockAtomicTerm) name() string {
	return ipBlockTerm.String()
}

func (ipBlockTerm *ipBlockAtomicTerm) AsSelector() (string, bool) {
	return toImplement, false
}

func (ipBlockTerm *ipBlockAtomicTerm) GetBlock() *netset.IPBlock {
	block := ipBlockTerm.Block
	if ipBlockTerm.isNegation() {
		block = block.Complementary()
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
	return &ipBlockAtomicTerm{IPBlock: &topology.IPBlock{Block: ipBlockTerm.Block.Complementary(), OriginalIP: ""},
		atomicTerm: atomicTerm{}}
}

// returns true iff otherAt is negation of tagTerm; either syntactically or semantically
func (ipBlockTerm *ipBlockAtomicTerm) isNegateOf(otherAtom atomic) bool {
	otherBlock := otherAtom.GetBlock()
	if otherBlock == nil {
		return false
	}
	return ipBlockTerm.GetBlock().Equal(otherBlock.Complementary())
}

// returns true iff ipBlocks otherAt and otherAtom are disjoint
func (ipBlockTerm *ipBlockAtomicTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	block := ipBlockTerm.GetBlock()
	otherBlock := otherAtom.GetBlock()
	if otherBlock == nil {
		return true // otherAtom is not an IPBlock; external IP block is disjoint to tag/group terms referring to VMs
	}
	return !block.Overlap(otherBlock)
}

// returns true iff ipBlock tagTerm is superset of ipBlock otherAtom
func (ipBlockTerm *ipBlockAtomicTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	if otherAtom.GetBlock() == nil {
		return false
	}
	return ipBlockTerm.negate().disjoint(otherAtom, hints)
}

// Translates RuleIPBlock  it into []*Conjunction
// 3 relevant types:
// 1. tautology: 0.0.0.0/0; if one of the blocks of a RuleIPBlock is a tautology then it overrides all other blocks
// 2. External IP addr - these will be further translated into IPBlockTerm
// 3. Internal IP addr - todo
func getConjunctionForIPBlock(ipBlocks []*topology.RuleIPBlock) (ipBlocksConjunctions []*Conjunction, isTautology bool) {
	ipBlocksConjunctions = []*Conjunction{}
	for _, ipBlock := range ipBlocks {
		if ipBlock.IsAll() {
			return []*Conjunction{{&tautology{}}}, true
		}
		if ipBlock.HasExternal() {
			externalIPBlock := &topology.IPBlock{Block: ipBlock.ExternalRange, OriginalIP: ipBlock.OriginalIP}
			ipBlocksConjunctions = append(ipBlocksConjunctions, &Conjunction{&ipBlockAtomicTerm{atomicTerm: atomicTerm{},
				IPBlock: externalIPBlock}})
		}
		// if ipBlock.HasInternal() todo: handle internal IPBlocks
	}
	return ipBlocksConjunctions, isTautology
}
