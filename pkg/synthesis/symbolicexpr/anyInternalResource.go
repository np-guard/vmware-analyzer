package symbolicexpr

// anyInternalResource represents (any) term over only internal resources

import (
	"github.com/np-guard/models/pkg/netset"
)

// following 4 functions are false since anyInternalResource is a non-trivial subset of internal resources

func (anyInternalResource) IsTautology() bool {
	return false
}

func (anyInternalResource) IsContradiction() bool {
	return false
}

func (anyInternalResource) IsAllGroups() bool {
	return false
}

func (anyInternalResource) IsNoGroup() bool {
	return false
}

func (anyInternalResource) GetExternalBlock() *netset.IPBlock {
	return nil
}

func (anyInternalResource) isInternalOnly() bool {
	return true
}
