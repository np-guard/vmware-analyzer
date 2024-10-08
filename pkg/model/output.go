package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/common"
)

const (
	TextFormat = "txt"
	DotFormat  = "dot"
)

type OutputParameters struct {
	Format   string
	FileName string
	VMs      []string
}

func (c *config) output(params OutputParameters) (res string, err error) {
	filteredConn := c.analyzedConnectivity.Filter(params.VMs)

	switch params.Format {
	case TextFormat:
		res = filteredConn.String()
	case DotFormat:
		res = createDotGraph(filteredConn.toSlice()).String()
	}
	if params.FileName != "" {
		err := common.WriteToFile(params.FileName, res)
		if err != nil {
			return "", err
		}
	}
	return res, nil
}

func createDotGraph(conns []connMapEntry) *common.DotGraph {
	g := common.NewDotGraph()
	for _, e := range conns {
		g.AddEdge(e.src, e.dst, e.conn.String())
	}
	return g
}
