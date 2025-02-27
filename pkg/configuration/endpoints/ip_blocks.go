package endpoints

import (
	"github.com/np-guard/models/pkg/netset"
)

// a base struct to represent external endpoints, segments and rule block
type ipBlock struct {
	Block *netset.IPBlock
	name  string
}
type RuleIPBlock struct {
	ipBlock
	VMs []EP
}

func NewRuleIPBlock(name string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{ipBlock: ipBlock{name: name, Block: block}}
}

type Segment struct {
	ipBlock
	VMs []EP
}

func NewSegment(name string, block *netset.IPBlock) *Segment {
	return &Segment{ipBlock: ipBlock{name: name, Block: block}}
}
