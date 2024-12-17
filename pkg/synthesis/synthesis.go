package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

func NSXSynthesis(recourses *collector.ResourcesContainerModel, params model.OutputParameters) (string, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return "", err
	}
	config := parser.GetConfig()

	_ = config

	return "", nil
}
