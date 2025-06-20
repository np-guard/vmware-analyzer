package analyzer

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func computeConnectivity(c *configuration.Config, vmsFilter []string) connectivity.ConnMap {
	logging.Debugf("started computing connectivity on parsed NSX config")
	res := connectivity.ConnMap{}
	// make sure all vm pairs are in the result, by init with global default
	res.InitPairs(false, c.VMs, c.Endpoints(), vmsFilter)
	// iterate over all vm pairs in the initialized map at res, get the analysis result per pair
	for src, srcMap := range res {
		for dst := range srcMap {
			if src == dst {
				continue
			}
			conn := dfwAllowedConnections(c.FW, src, dst)

			if (src.IsExternal() && conn.ExplanationObj.NotDeterminedIngress.IsAll()) ||
				(dst.IsExternal() && conn.ExplanationObj.NotDeterminedEgress.IsAll()) {
				delete(srcMap, dst)
				continue // skip such pairs for which no connectivity was determined
			}

			res.Add(src, dst, conn)
		}
	}
	return res
}

func NSXConnectivityFromResourcesContainer(resources *collector.ResourcesContainerModel, params *common.OutputParameters) (
	*configuration.Config,
	connectivity.ConnMap,
	string,
	error) {
	config, err := configuration.ConfigFromResourcesContainer(resources, params)
	if err != nil {
		return nil, nil, "", err
	}
	connMap := computeConnectivity(config, params.VMs)
	res, err := connMap.GenConnectivityOutput(params)

	rulesNotEvaluated := connMap.RulesNotEvaluated(config.FW.AllRulesIDs)
	logging.Debugf("rules not evaluated:%v\n", rulesNotEvaluated)

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
