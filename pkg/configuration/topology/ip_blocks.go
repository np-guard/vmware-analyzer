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
	origIP      string
	VMs         []Endpoint
	ExternalIPs []Endpoint
}

func NewRuleIPBlock(ip string, block *netset.IPBlock) *RuleIPBlock {
	return &RuleIPBlock{origIP: ip, ipBlock: ipBlock{Block: block}}
}

type Segment struct {
	ipBlock
	name string
	VMs  []Endpoint
}

func NewSegment(name string, block *netset.IPBlock) *Segment {
	return &Segment{name: name, ipBlock: ipBlock{Block: block}}
}

///////////////////////

type ExternalIP struct {
	ipBlock
	cidr string
}

func NewExternalIP(block *netset.IPBlock) *ExternalIP {
	e := &ExternalIP{ipBlock: ipBlock{Block: block}}
	e.cidr = block.String()
	return e
}

func (ip *ExternalIP) Name() string   { return ip.cidr }
func (ip *ExternalIP) String() string { return ip.cidr }
func (ip *ExternalIP) Kind() string   { return "external IP" }
func (ip *ExternalIP) ID() string     { return ip.cidr }
func (ip *ExternalIP) InfoStr() []string {
	return []string{ip.Name(), ip.ID(), ip.Name()}
}
func (ip *ExternalIP) Tags() []string { return nil }
