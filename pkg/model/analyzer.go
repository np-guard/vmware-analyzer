package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel, params OutputParameters) (string, error) {
	config, err := configFromResourcesContainer(recourses, params.VMs)
	if err != nil {
		return "", err
	}

	res, err := config.genConnectivityOutput(params)

	return res, err
}

func NSXConnectivityFromResourcesContainerPlainText(recourses *collector.ResourcesContainerModel) (string, error) {
	return NSXConnectivityFromResourcesContainer(recourses, OutputParameters{Format: "txt"})
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
