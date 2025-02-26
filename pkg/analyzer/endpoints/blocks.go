package endpoints

import (
	"github.com/np-guard/models/pkg/netset"
)

type ipBlock struct {
	Block *netset.IPBlock
	name  string
}

type RuleBlock ipBlock

func NewRuleBlock(ip string) *RuleBlock {
	block, err := netset.IPBlockFromCidrOrAddress(ip)
	if err != nil {
		block, err = netset.IPBlockFromIPRangeStr(ip)
	}
	// todo - handle error
	return &RuleBlock{name: ip, Block: block}
}

type Segment struct {
	ipBlock
	VMs []EP
}

func NewSegment(name string, block *netset.IPBlock) *Segment {
	return &Segment{ipBlock: ipBlock{name: name, Block: block}}
}

