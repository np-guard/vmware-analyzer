package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

func NSXSynthesis(recourses *collector.ResourcesContainerModel, params model.OutputParameters) (string, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return "", err
	}
	config := parser.GetConfig()

	// in debug/verbose mode -- print the parsed config
	logging.Debugf("the parsed config details: %s", config.GetConfigInfoStr())

	// compute connectivity map from the parsed config
	config.ComputeConnectivity(params.VMs)

	return "", nil
}
