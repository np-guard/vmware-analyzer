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
	SegmentsVMs   []Endpoint
	ExternalIPs   []Endpoint
	Segments      []*Segment
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{IPBlock: IPBlock{Block: block, OriginalIP: ip}}
}

func (block *RuleIPBlock) IsAll() bool {
	return block.Block.Equal(netset.GetCidrAll())
}
func (block *RuleIPBlock) HasInternal() bool {
	return len(block.VMs) > 0
}
func (block *RuleIPBlock) HasExternal() bool {
	return !block.ExternalRange.IsEmpty()
}

func (block *RuleIPBlock) InternalInfo() ([]*Segment, []Endpoint, string) {
	if len(block.VMs) > len(block.SegmentsVMs) {
		return block.Segments, block.VMs, block.OriginalIP
	}
	return block.Segments, nil, block.OriginalIP
}
func (block *RuleIPBlock) ExternalInfo() *IPBlock {
	return &IPBlock{block.ExternalRange, block.OriginalIP}
}

type Segment struct {
	IPBlock
	name string
	VMs  []Endpoint
}

func NewSegment(name string, block *netset.IPBlock, subnetsNetworks []string) *Segment {
	return &Segment{name: name, IPBlock: IPBlock{Block: block, OriginalIP: strings.Join(subnetsNetworks, common.CommaSeparator)}}
}
