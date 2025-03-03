package topology

import (
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
)

// a base struct to represent external endpoints, segments and rule block
type IpBlock struct {
	Block      *netset.IPBlock
	OriginalIP string
}
type RuleIPBlock struct {
	IpBlock
	VMs         []Endpoint
	ExternalIPs []Endpoint
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{IpBlock: IpBlock{Block: block, OriginalIP: ip}}
}

type Segment struct {
	IpBlock
	name string
	VMs  []Endpoint
}

func NewSegment(name string, block *netset.IPBlock, subnetsNetworks []string) *Segment {
	return &Segment{name: name, IpBlock: IpBlock{Block: block, OriginalIP: strings.Join(subnetsNetworks, common.CommaSeparator)}}
}
