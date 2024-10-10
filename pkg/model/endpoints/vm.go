package endpoints

// intenal modeling for vmware endpoints
type VM struct {
	name string
	// address string
}

func (v *VM) Name() string {
	return v.name
}

func (v *VM) Kind() string {
	return "vm"
}

func NewVM(name string) *VM {
	return &VM{
		name: name,
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
