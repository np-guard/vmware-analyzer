package model

/*func (c *config) genConnectivityOutput(params common.OutputParameters) (res string, err error) {
	filteredConn := c.analyzedConnectivity.Filter(params.VMs)
	var g common.Graph
	switch params.Format {
	case common.JSONFormat:
		g = common.NewEdgesGraph("")
	case common.TextFormat:
		g = common.NewEdgesGraph("Analyzed connectivity:")
	case common.DotFormat, common.SvgFormat:
		g = common.NewDotGraph(false)
	}
	for _, e := range filteredConn.ToSlice() {
		if !e.Conn.Conn.IsEmpty() {
			g.AddEdge(e.Src, e.Dst, e.Conn.Conn)
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

func (c *config) genExplanationOutput() string {
	return fmt.Sprintf("\n\nExplanation section:\n%s", c.analyzedConnectivity.FullOutputWithExplanations())
}
*/
