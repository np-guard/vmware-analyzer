package model

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel, params common.OutputParameters) (
	ParsedNSXConfig, string, error) {
	config, err := configFromResourcesContainer(recourses, params)
	if err != nil {
		return nil, "", err
	}

	res, err := config.analyzedConnectivity.GenConnectivityOutput(params)

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

	return config, res, err
}

func configFromResourcesContainer(recourses *collector.ResourcesContainerModel, params common.OutputParameters) (*config, error) {
	parser := NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()

	// in debug/verbose mode -- print the parsed config
	logging.Debugf("the parsed config details: %s", config.GetConfigInfoStr(params.Color))

	// compute connectivity map from the parsed config
	config.ComputeConnectivity(params.VMs)

	return config, nil
}
