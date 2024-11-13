package synthesis

import (
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

func SynthesisConfig(resources *collector.ResourcesContainerModel, params model.OutputParameters) error {
	// segmentsToVms := //getSegmentsToVMs(resources)
	config, err := model.NSXConfigFromResourcesContainer(resources)
	if err != nil {
		return nil
	}
	_ = config
	// res := &synthesisRes{segments: segmentsToVms, rules: nil}
	// return res, nil
	return nil
}

// func getSegmentsToVMs(resources *collector.ResourcesContainerModel) SegmentsToVMs {
//	segmentsToVMs := SegmentsToVMs{}
//	for si := range resources.SegmentList {
//		segment := &resources.SegmentList[si]
//		vms := []*collector.VirtualMachine{} // todo []*endpoints.VM{}?
//		for pi := range segment.SegmentPorts {
//			att := *segment.SegmentPorts[pi].Attachment.Id
//			vni := resources.GetVirtualNetworkInterfaceByPort(att)
//			vm := resources.GetVirtualMachine(*vni.OwnerVmId)
//			vms = append(vms, vm)
//		}
//		segmentAndVMs := segmentsWithVMs{segment: segment, vms: vms}
//		segmentsToVMs[segment.Name()] = segmentAndVMs
//	}
//	return segmentsToVMs
// }

// todo handle default allow
