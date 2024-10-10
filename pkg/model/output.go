package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/common"
)

type OutputParameters struct {
	Format   string
	FileName string
	VMs      []string
}

func (c *config) output(params OutputParameters) (res string, err error) {
	filteredConn := c.analyzedConnectivity.Filter(params.VMs)
	return common.OutputGraph(params.FileName, params.Format,true, &filteredConn)
}

func (conn *connMap) CreateGraph(g common.Graph) {
	for _, e := range conn.toSlice() {
		g.AddEdge(e.src, e.dst, e.conn.String())
	}
}
