package endpoints


type EP interface {
	Name() string
	String() string
	Kind() string
	ID() string
	InfoStr() []string
	Tags() []string
}

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
