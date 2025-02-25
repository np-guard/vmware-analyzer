package topology

import (
	"github.com/np-guard/models/pkg/netset"
)

// a base struct to represent external endpoints, segments and rule block
type ipBlock struct {
	Block *netset.IPBlock
}
type RuleIPBlock struct {
	ipBlock
	origIP string
	VMs    []Endpoint
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{origIP: ip, ipBlock: ipBlock{Block: block}}
}

type SegmentNew struct {
	ipBlock
	name string
	VMs  []Endpoint
}

func NewSegmentNew(name string, block *netset.IPBlock) *SegmentNew {
	return &SegmentNew{name: name, ipBlock: ipBlock{Block: block}}
}
