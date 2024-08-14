package endpoints

// intenal modeling for vmware endpoints
type VM struct {
	name string
	// address string
}

func (v *VM) Name() string {
	return v.name
}

func NewVM(name string) *VM {
	return &VM{
		name: name,
	}
}
