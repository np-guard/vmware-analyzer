package topology

import (
	"github.com/np-guard/models/pkg/netset"
)

type ExternalIP struct {
	IPBlock
}

func NewExternalIP(block *netset.IPBlock) *ExternalIP {
	e := &ExternalIP{IPBlock: IPBlock{Block: block, OriginalIP: block.String()}}
	return e
}

func (ip *ExternalIP) Name() string   { return ip.OriginalIP }
func (ip *ExternalIP) String() string { return ip.OriginalIP }
func (ip *ExternalIP) Kind() string   { return "external IP" }
func (ip *ExternalIP) ID() string     { return ip.OriginalIP }
func (ip *ExternalIP) InfoStr() []string {
	return []string{ip.Name(), ip.ID(), ip.Name()}
}
func (ip *ExternalIP) Tags() []string         { return nil }
func (ip *ExternalIP) IPAddressesStr() string { return ip.OriginalIP }
