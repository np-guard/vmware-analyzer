package symbolicexpr

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

func TestIpBlockTerm(t *testing.T) {
	allIPBlock, _ := netset.IPBlockFromCidr("0.0.0.0/0")
	ipBlock1, _ := netset.IPBlockFromCidr("1.2.3.0/8")
	ipBlock2, _ := netset.IPBlockFromCidr("1.2.3.0/16")
	ipBlock3, _ := netset.IPBlockFromCidr("192.0.2.0/24")
	ipAddrSingle, _ := netset.IPBlockFromCidr("192.0.2.0/32")
	allIpBlockTerm := NewIPBlockTermTerm(&topology.IpBlock{Block: allIPBlock, OriginalIP: "0.0.0.0/0"})
	ipBlockTerm1 := NewIPBlockTermTerm(&topology.IpBlock{Block: ipBlock1, OriginalIP: "1.2.3.0/8"})
	ipBlockTerm2 := NewIPBlockTermTerm(&topology.IpBlock{Block: ipBlock2, OriginalIP: "1.2.3.0/16"})
	ipBlockTerm3 := NewIPBlockTermTerm(&topology.IpBlock{Block: ipBlock3, OriginalIP: "192.0.2.0/24"})
	ipAddrSingleTerm := NewIPBlockTermTerm(&topology.IpBlock{Block: ipAddrSingle, OriginalIP: "192.0.2.0"})
	fmt.Println("allIpBlockTerm is", allIpBlockTerm)
	fmt.Println("ipBlockTerm1 is", ipBlockTerm1)
	fmt.Println("ipBlockTerm2 is", ipBlockTerm2)
	fmt.Println("ipBlockTerm3 is", ipBlockTerm3)
	fmt.Println("ipAddrSingleTerm is", ipAddrSingleTerm)
	// checks String and Name
	require.Equal(t, "IP block in 0.0.0.0/0", allIpBlockTerm.String())
	require.Equal(t, "IP block in 192.0.2.0/24", ipBlockTerm3.String())
	require.Equal(t, "IP block in 192.0.2.0", ipAddrSingleTerm.String())
}
