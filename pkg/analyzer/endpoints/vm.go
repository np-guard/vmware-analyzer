package endpoints

import (
	"maps"
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

// VM intenal modeling for vmware endpoints
type VM struct {
	name        string
	uid         string
	tags        []string //todo: implement
	ipAddresses []string
	// address string
}

func (v *VM) ID() string {
	return v.uid
}

func (v *VM) Name() string {
	_ = v.tags // todo tmp
	return v.name
}

func (v *VM) String() string {
	return v.Name()
}

func (v *VM) Kind() string {
	return "vm"
}

func (v *VM) InfoStr() []string {
	return []string{v.Name(), v.ID(), strings.Join(v.IPAddresses(), common.CommaSeparator)}
}

func (v *VM) SetIPAddresses(ips []string) {
	v.ipAddresses = ips
}

func (v *VM) IPAddresses() []string {
	return v.ipAddresses
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

func NewVM(name, uid string) *VM {
	return &VM{
		name: name,
		uid:  uid,
		tags: []string{}, // todo tmp
	}
}

// todo = move to endpoint.go:
func Intersection(a, b []EP) []EP {
	res := []EP{}
	aKeys := map[string]bool{}
	for _, aVM := range a {
		aKeys[aVM.Name()] = true
	}
	for _, bVM := range b {
		if aKeys[bVM.Name()] {
			res = append(res, bVM)
		}
	}
	return res
}

func Subtract(a, b []EP) []EP {
	res := []EP{}
	bKeys := map[string]bool{}
	for _, bVM := range b {
		bKeys[bVM.Name()] = true
	}
	for _, aVM := range a {
		if !bKeys[aVM.Name()] {
			res = append(res, aVM)
		}
	}
	return res
}

func Compact(a []EP) []EP {
	set := map[EP]bool{}
	for _, aVM := range a {
		set[aVM] = true
	}
	return slices.Collect(maps.Keys(set))
}
