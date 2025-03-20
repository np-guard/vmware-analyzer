package symbolicexpr

import "github.com/np-guard/models/pkg/netset"

// abstraction of an NSX originate group or over VMs originating from an NSX internal cidr

// following 4 functions are false since an abstractGroupTerm is an abstraction of non-trivial groups

func (abstractGroupTerm) IsTautology() bool {
	return false
}

func (abstractGroupTerm) IsContradiction() bool {
	return false
}

func (abstractGroupTerm) IsAllGroups() bool {
	return false
}

func (abstractGroupTerm) IsNoGroup() bool {
	return false
}

//

func (abstractGroup abstractGroupTerm) name() string {
	return abstractGroup.group.Name()
}

func (abstractGroupTerm) GetBlock() *netset.IPBlock {
	return nil
}
