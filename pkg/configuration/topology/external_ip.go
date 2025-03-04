package topology

import (
	"github.com/np-guard/models/pkg/netset"
)

type ExternalIP struct {
	ipBlock
}

func NewExternalIP(block *netset.IPBlock) *ExternalIP {
	e := &ExternalIP{ipBlock: ipBlock{Block: block, originalIP: block.String()}}
	return e
}

func (ip *ExternalIP) Name() string   { return ip.originalIP }
func (ip *ExternalIP) String() string { return ip.originalIP }
func (ip *ExternalIP) Kind() string   { return "external IP" }
func (ip *ExternalIP) ID() string     { return ip.originalIP }
func (ip *ExternalIP) InfoStr() []string {
	return []string{ip.Name(), ip.ID(), ip.Name()}
}
func (ip *ExternalIP) Tags() []string         { return nil }
func (ip *ExternalIP) IPAddressesStr() string { return ip.originalIP }
