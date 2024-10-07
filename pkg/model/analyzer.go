package model

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/output"
)

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel) (output.Graph, error) {
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

	// TODO: add cli params to filter vms
	// return output string of connectivity map
	return config.AnalyzedConnectivity([]string{"New Virtual Machine", "New-VM-1"}), nil
}
