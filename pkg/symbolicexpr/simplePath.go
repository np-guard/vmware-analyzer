package symbolicexpr

func (path *simplePath) string() string {
	return path.src.string() + " -> " + path.dst.string()
}
