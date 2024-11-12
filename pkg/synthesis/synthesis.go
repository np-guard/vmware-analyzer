package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

type synthesisRes struct {
	segments SegmentsToVMs
	rules    []*abstractRules // with default deny
}

func SynthesisConfig(recourses *collector.ResourcesContainerModel, params model.OutputParameters) (*synthesisRes, error) {
	config, err := model.NSXConfigFromResourcesContainer(recourses)
	if err != nil {
		return nil, err
	}
	_ = config
	return nil, nil
}

// todo handle default allow
