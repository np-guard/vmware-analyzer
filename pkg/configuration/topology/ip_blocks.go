package topology

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
)

// a base struct to represent external endpoints, segments and rule block
type IPBlock struct {
	Block      *netset.IPBlock
	OriginalIP string
}

func (ipb *IPBlock) String() string {
	return fmt.Sprintf("block: %s , origIP: %s", ipb.Block.String(), ipb.OriginalIP)
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

func (block *RuleIPBlock) String() string {
	ipblockStr := block.IPBlock.String()
	externalRangeStr := fmt.Sprintf("external range: %s", block.ExternalRange.String())
	vms := fmt.Sprintf("vms: %s", common.JoinStringifiedSlice(block.VMs, common.CommaSeparator))
	extIPs := fmt.Sprintf("ExternalIPs: %s", common.JoinStringifiedSlice(block.ExternalIPs, common.CommaSeparator))
	segments := fmt.Sprintf("Segments: %s", common.JoinStringifiedSlice(block.Segments, common.CommaSeparator))
	segmentsVMs := fmt.Sprintf("SegmentsVMs: %s", common.JoinStringifiedSlice(block.SegmentsVMs, common.CommaSeparator))

	return strings.Join([]string{ipblockStr, externalRangeStr, vms, extIPs, segments, segmentsVMs}, common.NewLine)
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

func (s *Segment) String() string {
	return "(segment)" + s.Name
}

func NewSegment(name string, block *netset.IPBlock, subnetsNetworks []string) *Segment {
	return &Segment{Name: name, IPBlock: IPBlock{Block: block, OriginalIP: strings.Join(subnetsNetworks, common.CommaSeparator)}}
}
