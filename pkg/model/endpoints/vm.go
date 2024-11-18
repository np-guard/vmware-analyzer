package endpoints

// intenal modeling for vmware endpoints
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
	return v.name
}

func (v *VM) Kind() string {
	return "vm"
}

func NewVM(name, uid string) *VM {
	return &VM{
		name: name,
		uid:  uid,
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
