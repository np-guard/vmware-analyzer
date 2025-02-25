package endpoints

import (
	"maps"
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

// VM captures vmware VM with its relevant properties
type VM struct {
	name        string
	uid         string   // NSX UID of this VM
	tags        []string // NSX tags attached to this VM
	ipAddresses []string // list of IP addresses of this VM's interfaces
}

func NewVM(name, uid string) *VM {
	return &VM{
		name: name,
		uid:  uid,
	}
}

func (v *VM) ID() string {
	return v.uid
}

func (v *VM) Name() string {
	return v.name
}

func (v *VM) String() string {
	return v.Name()
}

func (v *VM) Kind() string {
	return "VM"
}

func (v *VM) SetIPAddresses(ips []string) {
	v.ipAddresses = ips
}

func (v *VM) IPAddresses() []string {
	return v.ipAddresses
}

func (v *VM) IPAddressesStr() string {
	return strings.Join(v.ipAddresses, common.CommaSeparator)
}

func (v *VM) AddTag(t string) {
	if slices.Contains(v.tags, t) {
		return
	}
	v.tags = append(v.tags, t)
}

func (v *VM) Tags() []string {
	return v.tags
}

func Intersection(a, b []*VM) []*VM {
	res := []*VM{}
	aKeys := map[string]bool{}
	for _, aVM := range a {
		aKeys[aVM.name] = true
	}
	for _, bVM := range b {
		if aKeys[bVM.name] {
			res = append(res, bVM)
		}
	}
	return res
}

func Subtract(a, b []*VM) []*VM {
	res := []*VM{}
	bKeys := map[string]bool{}
	for _, bVM := range b {
		bKeys[bVM.name] = true
	}
	for _, aVM := range a {
		if !bKeys[aVM.name] {
			res = append(res, aVM)
		}
	}
	return res
}

func Compact(a []*VM) []*VM {
	set := map[*VM]bool{}
	for _, aVM := range a {
		set[aVM] = true
	}
	return slices.Collect(maps.Keys(set))
}
