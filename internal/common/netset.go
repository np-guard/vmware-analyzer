package common

import "github.com/np-guard/models/pkg/netset"

func IPBlockFromCidrOrAddressOrIPRange(ip string) (*netset.IPBlock, error) {
	block, err := netset.IPBlockFromCidrOrAddress(ip)
	if err != nil {
		block, err = netset.IPBlockFromIPRangeStr(ip)
	}
	return block, err
}

func IPBlockShortString(set *netset.IPBlock) string {
	// look for the shortest name:
	asCidrs, asRanges := set.String(), set.ToIPRanges()
	res := asCidrs
	if len(asRanges) < len(asCidrs) {
		res = asRanges
	}
	return res
}
