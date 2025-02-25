package endpoints

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

type IPBlock struct {
	name string
}

func (b *IPBlock) Name() string {
	return b.name
}

func (b *IPBlock) String() string {
	return b.Name()
}

func (b *IPBlock) ID() string {
	return b.Name()
}

func (b *IPBlock) Kind() string {
	return "external"
}

func (b *IPBlock) InfoStr() []string {
	return []string{b.Name(), b.ID(), strings.Join([]string{b.Name()}, common.CommaSeparator)}
}

func (b *IPBlock) Tags() []string {
	return nil
}
