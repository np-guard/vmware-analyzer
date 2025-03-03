package analyzer

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func computeConnectivity(c *configuration.Config, vmsFilter []string) connectivity.ConnMap {
	logging.Debugf("compute connectivity on parsed config")
	res := connectivity.ConnMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.InitPairs(false, append(c.Vms,c.ExternalIPs...), vmsFilter)
	// iterate over all vm pairs in the initialized map at res, get the analysis result per pair
	for src, srcMap := range res {
		for dst := range srcMap {
			if src == dst {
				continue
			}
			conn := dfwAllowedConnections(c.Fw, src, dst)
			res.Add(src, dst, conn)
		}
	}
	return res
}

func NSXConnectivityFromResourcesContainer(resources *collector.ResourcesContainerModel, params common.OutputParameters) (
	configuration.ParsedNSXConfig,
	connectivity.ConnMap,
	string,
	error) {
	config, err := configuration.ConfigFromResourcesContainer(resources, params.Color)
	if err != nil {
		return nil, nil, "", err
	}
	connMap := computeConnectivity(config, params.VMs)
	res, err := connMap.GenConnectivityOutput(params)

	//nolint:gocritic // temporarily keep commented-out code
	/*allowed, denied := config.analyzedConnectivity.GetDisjointExplanationsPerEndpoints("A", "B")
	fmt.Println("allowed disjoint explains:")
	for _, a := range allowed {
		fmt.Printf("conn: %s, ingress rules: %s, egress rules: %s\n", a.Conn.String(),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.IngressExplanations,
				func(s *connectivity.RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.EgressExplanations,
				func(s *connectivity.RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
		)
	}
	fmt.Println("denied disjoint explains:")
	for _, a := range denied {
		fmt.Printf("conn: %s, ingress rules: %s, egress rules: %s\n", a.Conn.String(),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.IngressExplanations,
				func(s *connectivity.RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
			common.JoinCustomStrFuncSlice(a.ExplanationObj.EgressExplanations,
				func(s *connectivity.RuleAndConn) string { return fmt.Sprintf("%d", s.RuleID) }, " ; "),
		)
	}*/

	return config, connMap, res, err
}
