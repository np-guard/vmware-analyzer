package symbolicexpr

// ipBlockTerm represents external IPs

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func NewIPBlockTerm(ipBlock *topology.IPBlock) *externalIPTerm {
	// todo: dump if ipBlock has internal address
	return &externalIPTerm{atomicTerm: atomicTerm{}, IPBlock: ipBlock}
}

// OrigIP is non-empty for an ipTerm that is in its original rule form, or a negation of such ipTerm
// once we have more than one ipTerm in a Conjunction we merge; and then the OrigIP component is lost

func (ipBlockTerm *externalIPTerm) String() string {
	var ipStr string
	if ipBlockTerm.Block.IsEmpty() {
		ipStr = "the empty block"
	} else {
		ipStr = ipBlockTerm.Block.String()
	}
	// prefer the OrigIP if exists
	origIP := ipBlockTerm.OriginalIP
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

func (ipBlockTerm *externalIPTerm) IsTautology() bool {
	return false
}

func (ipBlockTerm *externalIPTerm) IsAllGroups() bool {
	return false
}

// IsNoGroup externalIPTerm neq 0.0.0.0/0 presents external addresses, thus IsNoGroup is true
func (ipBlockTerm *externalIPTerm) IsNoGroup() bool {
	return true
}

// IsContradiction true iff the ipBlock is empty
func (ipBlockTerm *externalIPTerm) IsContradiction() bool {
	return ipBlockTerm.GetExternalBlock().IsEmpty()
}

//

func (ipBlockTerm *externalIPTerm) name() string {
	return ipBlockTerm.String()
}

func (ipBlockTerm *externalIPTerm) AsSelector() (string, bool) {
	return toImplement, false
}

func (ipBlockTerm *externalIPTerm) GetExternalBlock() *netset.IPBlock {
	block := ipBlockTerm.Block
	if ipBlockTerm.isNegation() {
		block = block.Complementary()
	}
	return block
}

// negate an externalIPTerm; if it has the OrigIP component then uses neg; otherwise complement the IP block
func (ipBlockTerm *externalIPTerm) negate() atomic {
	if ipBlockTerm.OriginalIP != "" { // orig block from rule
		return &externalIPTerm{IPBlock: &topology.IPBlock{Block: ipBlockTerm.Block, OriginalIP: ipBlockTerm.OriginalIP},
			atomicTerm: atomicTerm{neg: !ipBlockTerm.neg}}
	}
	// block not kept in the form of original rule form
	return &externalIPTerm{IPBlock: &topology.IPBlock{Block: ipBlockTerm.Block.Complementary(), OriginalIP: ""},
		atomicTerm: atomicTerm{}}
}

// returns true iff otherAt is negation of tagTerm; either syntactically or semantically
func (ipBlockTerm *externalIPTerm) isNegateOf(otherAtom atomic) bool {
	otherBlock := otherAtom.GetExternalBlock()
	if otherBlock == nil {
		return false
	}
	return ipBlockTerm.GetExternalBlock().Equal(otherBlock.Complementary())
}

// returns true iff ipBlocks otherAt and otherAtom are disjoint
func (ipBlockTerm *externalIPTerm) disjoint(otherAtom atomic, hints *Hints) bool {
	block := ipBlockTerm.GetExternalBlock()
	otherBlock := otherAtom.GetExternalBlock()
	if otherBlock == nil {
		return true // otherAtom is not an IPBlock; external IP block is disjoint to tag/group terms referring to VMs
	}
	return !block.Overlap(otherBlock)
}

// returns true iff ipBlock tagTerm is superset of ipBlock otherAtom
func (ipBlockTerm *externalIPTerm) supersetOf(otherAtom atomic, hints *Hints) bool {
	if otherAtom.GetExternalBlock() == nil {
		return false
	}
	return ipBlockTerm.negate().disjoint(otherAtom, hints)
}

func (*externalIPTerm) isInternalOnly() bool {
	return false
}

func (*externalIPTerm) IsAllExternal() bool {
	return false
}

// Translates RuleIPBlock it into []*Conjunction
// 3 relevant types:
// 1. tautology: 0.0.0.0/0; if one of the blocks of a RuleIPBlock is a tautology then it overrides all other blocks
// 2. External IP addr - these are further translated into externalIPTerm
// 3. Segments - these are further translated in segmentTerm
// 4. Internal IP addr - in case not all VMs are covered by segments, the *entire* IP is handled as internalIPTerm
func getConjunctionForIPBlock(ruleIPBlocks []*topology.RuleIPBlock, isExternalRelevant bool) (externalIPBlocksConjunctions,
	internalIPBlocksConjunctions []*Conjunction, isTautology bool) {
	externalIPBlocksConjunctions = []*Conjunction{}
	for _, ruleIPBlock := range ruleIPBlocks {
		if ruleIPBlock.IsAll() {
			return []*Conjunction{{&tautology{}}}, nil, true
		}
		if isExternalRelevant && ruleIPBlock.HasExternal() {
			externalIPBlock := &topology.IPBlock{Block: ruleIPBlock.ExternalRange, OriginalIP: ruleIPBlock.OriginalIP}
			externalIPBlocksConjunctions = append(externalIPBlocksConjunctions, &Conjunction{&externalIPTerm{atomicTerm: atomicTerm{},
				IPBlock: externalIPBlock}})
		}
		for _, segment := range ruleIPBlock.Segments {
			newSegmentTerm := NewSegmentTerm(segment)
			internalIPBlocksConjunctions = append(internalIPBlocksConjunctions, &Conjunction{newSegmentTerm})
		}
		// if there is *any* VM not in subnet then the *entire* IP is handled as internalIPTerm
		if ruleIPBlock.HasVMsNotInSubnet() {
			newInternalIPTerm := NewInternalIPTerm(ruleIPBlock)
			internalIPBlocksConjunctions = append(internalIPBlocksConjunctions, &Conjunction{newInternalIPTerm})
		}
	}
	return externalIPBlocksConjunctions, internalIPBlocksConjunctions, isTautology
}

func (externalIPTerm) getInternalBlock() *netset.IPBlock {
	return nil
}
