package topology

type Endpoint interface {
	Name() string
	String() string
	Kind() string
	ID() string
	InfoStr() []string
	Tags() []string
	IPAddressesStr() string
}

func Intersection(a, b []Endpoint) []Endpoint {
	res := []Endpoint{}
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

func Subtract(a, b []Endpoint) []Endpoint {
	res := []Endpoint{}
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
