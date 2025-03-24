package connectivity

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/internal/common"
)

func (c ConnMap) GenConnectivityOutput(params common.OutputParameters) (res string, err error) {
	filteredConn := c.filter(params.VMs)
	var g common.Graph
	switch params.Format {
	case common.JSONFormat:
		g = common.NewEdgesGraph("", []string{}, false)
	case common.TextFormat:
		g = common.NewEdgesGraph(common.AnalyzedConnectivityHeader, []string{"Source", "Destination", "Permitted connections"}, params.Color)
	case common.DotFormat, common.SvgFormat:
		g = common.NewDotGraph(false)
	default:
		return "", fmt.Errorf("unsupported format %s", params.Format)
	}
	for _, e := range filteredConn.toSlice() {
		if !e.DetailedConn.Conn.IsEmpty() {
			g.AddEdge(e.Src, e.Dst, e.DetailedConn.Conn)
		}
	}
	res, err = common.OutputGraph(g, params.FileName, params.Format)
	if err != nil {
		return res, err
	}
	if params.Format == common.TextFormat && params.Explain {
		res += c.genExplanationOutput()
	}
	return res, nil
}
