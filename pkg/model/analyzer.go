package model

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
)

func NSXConnectivityFromResourcesContainer(recourses *collector.ResourcesContainerModel) (string, error) {
	parser := NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return "", err
	}
	config := parser.GetConfig()
	config.ComputeConnectivity()

	// TODO: add cli params to filter vms
	return config.AnalyzedConnectivity([]string{"New Virtual Machine", "New-VM-1"}), nil
}
