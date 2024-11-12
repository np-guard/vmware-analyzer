package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func NSXConfigFromResourcesContainer(recourses *collector.ResourcesContainerModel) (*Config, error) {
	parser := NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()

	// in debug/verbose mode -- print the parsed config
	logging.Debugf("the parsed config details: %s", config.getConfigInfoStr())

	return config, nil
}

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel, params OutputParameters) (string, error) {
	config, err := NSXConfigFromResourcesContainer(recourses)
	if err != nil {
		return "", err
	}

	// compute connectivity map from the parsed config
	config.ComputeConnectivity()

	return config.output(params)
}
