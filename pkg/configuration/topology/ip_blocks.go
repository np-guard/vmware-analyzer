package topology

import (
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
)

// a base struct to represent external endpoints, segments and rule block
type IPBlock struct {
	Block      *netset.IPBlock
	OriginalIP string
}
type RuleIPBlock struct {
	IPBlock
	ExternalRange *netset.IPBlock
	VMs           []Endpoint
	ExternalIPs   []Endpoint
	Segments      []*Segment // the segments that their subnet is a subset of this block
	SegmentsVMs   []Endpoint // all the VMs in the block segments
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{IPBlock: IPBlock{Block: block, OriginalIP: ip}}
}

func (block *RuleIPBlock) IsAll() bool {
	return block.Block.Equal(netset.GetCidrAll())
}

func (block *RuleIPBlock) HasExternal() bool {
	return !block.ExternalRange.IsEmpty()
}

func (block *RuleIPBlock) ExternalIPBlock() *IPBlock {
	return &IPBlock{block.ExternalRange, block.OriginalIP}
}

func (block *RuleIPBlock) HasInternalIPNotInSegments() bool {
	ip := block.Block
	ip = ip.Subtract(block.ExternalRange)
	for _, segment := range block.Segments {
		ip = ip.Subtract(segment.Block)
	}
	return !ip.IsEmpty()
}

type Segment struct {
	IPBlock
	Name string
	VMs  []Endpoint
}

func NewSegment(name string, block *netset.IPBlock, subnetsNetworks []string) *Segment {
	return &Segment{Name: name, IPBlock: IPBlock{Block: block, OriginalIP: strings.Join(subnetsNetworks, common.CommaSeparator)}}
}
