package topology

import (
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

func (v *VM) InfoStr() []string {
	return []string{v.Name(), v.ID(), strings.Join(v.IPAddresses(), common.CommaSeparator)}
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
func (v *VM) IsExternal() bool {return false}

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
