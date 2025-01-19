package endpoints

import "slices"

// VM intenal modeling for vmware endpoints
type VM struct {
	name string
	uid  string
	tags []string //todo: implement
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
