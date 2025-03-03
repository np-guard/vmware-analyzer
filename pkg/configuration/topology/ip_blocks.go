package topology

import (
	"github.com/np-guard/models/pkg/netset"
)

// a base struct to represent external endpoints, segments and rule block
type IpBlock struct {
	Block *netset.IPBlock
}
type RuleIPBlock struct {
	IpBlock
	OrigIP string
	VMs    []Endpoint
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{OrigIP: ip, IpBlock: IpBlock{Block: block}}
}

type Segment struct {
	IpBlock
	name string
	VMs  []Endpoint
}

func NewSegment(name string, block *netset.IPBlock) *Segment {
	return &Segment{name: name, IpBlock: IpBlock{Block: block}}
}
