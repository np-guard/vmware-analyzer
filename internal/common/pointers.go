package common

// SafePointerDeref dereferences pointer if not nil, else returns empty object
func SafePointerDeref[T any](p *T) T {
	if p == nil {
		var x T
		return x
	}
	return *p
}

// PointerTo is used as shorthand to extract pointer from const value
func PointerTo[T any](t T) *T {
	return &t
}
