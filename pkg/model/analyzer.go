package model

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
)

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel) (Config, error) {
	parser := NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()

	// in debug/verbose mode-- print the parsed config
	fmt.Println("the parsed config details:")
	fmt.Println(config.getConfigInfoStr())

	// compute connectivity map from the parsed config
	config.ComputeConnectivity()

	return config, nil
}
