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
