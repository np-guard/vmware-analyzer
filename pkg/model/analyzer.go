package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func configFromResourcesContainer(recourses *collector.ResourcesContainerModel) (*config, error) {
	parser := NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()

	// in debug/verbose mode -- print the parsed config
	logging.Debugf("the parsed config details: %s", config.getConfigInfoStr())

	// compute connectivity map from the parsed config
	config.ComputeConnectivity()
	return config, nil
}

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel, params OutputParameters) (string, error) {
	config, err := configFromResourcesContainer(recourses)
	if err != nil {
		return "", err
	}
	return config.output(params)
}