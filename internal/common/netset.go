package common

import "github.com/np-guard/models/pkg/netset"

func NetsetShortString(set *netset.IPBlock) string {
	// look for the shortest name:
	asCidrs, asRanges := set.String(), set.ToIPRanges()
	res := asCidrs
	if len(asRanges) < len(asCidrs) {
		res = asRanges
	}
	return res
}
