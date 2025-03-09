package topology

import (
	"github.com/np-guard/models/pkg/netset"
)

type ExternalIP struct {
	IPBlock
}

func NewExternalIP(block *netset.IPBlock) *ExternalIP {
	// look for the shortest name:
	asCidrs, asRanges := block.String(), block.ToIPRanges()
	origIP := asCidrs
	if len(asRanges) < len(asCidrs) {
		origIP = asRanges
	}
	e := &ExternalIP{IPBlock: IPBlock{Block: block, OriginalIP: origIP}}
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
func (ip *ExternalIP) IsExternal() bool       { return true }
