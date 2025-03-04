package topology

import (
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
)

// a base struct to represent external endpoints, segments and rule block
type ipBlock struct {
	Block      *netset.IPBlock
	originalIP string
}
type RuleIPBlock struct {
	ipBlock
	VMs         []Endpoint
	ExternalIPs []Endpoint
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{ipBlock: ipBlock{Block: block, originalIP: ip}}
}

type SegmentNew struct {
	ipBlock
	name string
	VMs  []Endpoint
}

func NewSegmentNew(name string, block *netset.IPBlock, subnetsNetworks []string) *SegmentNew {
	return &SegmentNew{name: name, ipBlock: ipBlock{Block: block, originalIP: strings.Join(subnetsNetworks, common.CommaSeparator)}}
}
