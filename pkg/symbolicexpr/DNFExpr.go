package symbolicexpr

import "strings"

func (d *DNFExpr) string() string {
	resArray := make([]string, len(*d))
	for i, c := range *d {
		resArray[i] = c.string()
	}
	return "(" + strings.Join(resArray, " or\n") + ")"
}

func (d *DNFExpr) add(c Conjunction) *DNFExpr {
	if len(c) == 0 {
		return d
	}
	res := append(*d, c)
	return &res
}
