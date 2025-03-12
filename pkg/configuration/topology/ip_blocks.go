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
	internal InternalRuleIPBlock
	external ExternalRuleIPBlock
}
type InternalRuleIPBlock struct {
	OriginalIP string
	VMs         []Endpoint
	Segments    []*Segment
}
type ExternalRuleIPBlock struct {
	IPBlock
	ExternalIPs []Endpoint
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{IPBlock: IPBlock{Block: block, OriginalIP: ip}}
}

type Segment struct {
	IPBlock
	name string
	VMs  []Endpoint
}

func NewSegment(name string, block *netset.IPBlock, subnetsNetworks []string) *Segment {
	return &Segment{name: name, IPBlock: IPBlock{Block: block, OriginalIP: strings.Join(subnetsNetworks, common.CommaSeparator)}}
}
