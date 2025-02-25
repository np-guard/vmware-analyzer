package endpoints

type EP interface {
	Name() string
	String() string
	Kind() string
	ID() string
	InfoStr() []string
	Tags() []string
}
