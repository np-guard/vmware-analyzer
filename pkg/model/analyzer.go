package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel, params common.OutputParameters) (string, error) {
	config, err := configFromResourcesContainer(recourses, params.VMs)
	if err != nil {
		return "", err
	}

	res, err := config.analyzedConnectivity.GenConnectivityOutput(params)

	return res, err
}

func NSXConnectivityFromResourcesContainerPlainText(recourses *collector.ResourcesContainerModel) (string, error) {
	return NSXConnectivityFromResourcesContainer(recourses, common.OutputParameters{Format: common.TextFormat})
}

func configFromResourcesContainer(recourses *collector.ResourcesContainerModel, vmsFilter []string) (*config, error) {
	parser := NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()

	// in debug/verbose mode -- print the parsed config
	logging.Debugf("the parsed config details: %s", config.getConfigInfoStr())

	// compute connectivity map from the parsed config
	config.ComputeConnectivity(vmsFilter)
	//config.analyzedConnectivity.GetExplanationPerConnection("A", "B", netset.NewTCPTransport(1, 65535, 445, 445))

	//config.analyzedConnectivity.GetExplanationPerConnection("A", "B", netset.AllICMPTransport())
	return config, nil
}
