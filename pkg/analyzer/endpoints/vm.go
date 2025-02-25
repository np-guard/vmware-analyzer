package endpoints

import (
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

// VM intenal modeling for vmware endpoints
type VM struct {
	name        string
	uid         string
	tags        []string
	ipAddresses []string
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
		tags: []string{},
	}
}

