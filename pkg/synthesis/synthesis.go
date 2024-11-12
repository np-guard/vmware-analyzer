package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

func SynthesisConfig(recourses *collector.ResourcesContainerModel, params model.OutputParameters) error {
	config, err := model.NSXConfigFromResourcesContainer(recourses)
	if err != nil {
		return err
	}
	_ = config
	return nil
}
