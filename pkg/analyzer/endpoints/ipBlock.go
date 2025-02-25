package endpoints

import (
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
)

type IPBlock struct {
	name string
	netset.IPBlock
}

func (b *IPBlock) Name() string {
	// todo
	return b.name
}

func (b *IPBlock) String() string {
	// todo
	return b.Name()
}

func (b *IPBlock) ID() string {
	// todo
	return b.Name()
}

func (b *IPBlock) Kind() string {
	return "block"
}

func (b *IPBlock) InfoStr() []string {
	// todo
	return []string{b.Name(), b.ID(), strings.Join([]string{b.Name()}, common.CommaSeparator)}
}

func (b *IPBlock) Tags() []string {
	return nil
}
