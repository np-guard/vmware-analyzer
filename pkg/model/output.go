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
	var g common.Graph
	switch params.Format {
	case common.JSONFormat:
		g = common.NewEdgesGraph("")
	case common.TextFormat:
		g = common.NewEdgesGraph("analyzed connectivity")
	case common.DotFormat, common.SvgFormat:
		g = common.NewDotGraph(false)
	}
	for _, e := range filteredConn.ToSlice() {
		if !e.Conn.Conn.IsEmpty() {
			g.AddEdge(e.Src, e.Dst, e.Conn.Conn)
		}
	}
	return common.OutputGraph(g, params.FileName, params.Format)
}
