package connectivity

import "github.com/np-guard/vmware-analyzer/pkg/common"

func (c ConnMap) GenTextualConnectivityOutput() (res string, err error) {
	return c.GenConnectivityOutput(common.OutputParameters{Format: common.TextFormat})
}

func (c ConnMap) GenConnectivityOutput(params common.OutputParameters) (res string, err error) {
	filteredConn := c.filter(params.VMs)
	var g common.Graph
	switch params.Format {
	case common.JSONFormat:
		g = common.NewEdgesGraph("")
	case common.TextFormat:
		g = common.NewEdgesGraph("Analyzed connectivity:")
	case common.DotFormat, common.SvgFormat:
		g = common.NewDotGraph(false)
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
