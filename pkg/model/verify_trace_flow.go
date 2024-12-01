package model

import "github.com/np-guard/vmware-analyzer/pkg/collector"

func verifyTraceflow(recourses *collector.ResourcesContainerModel, server collector.ServerData) error {
	config, err := configFromResourcesContainer(recourses)
	if err != nil {
		return err
	}
	ips := []string{}
	for uid := range config.vmsMap {
		vmIps := recourses.GetVirtualMachineAddresses(uid)
		// ips = append(ips, vmIps...) // todo
		if len(vmIps) > 0 {
			ips = append(ips, vmIps[0])
		}
	}
	protocols := []collector.TraceFlowProtocol{
		{Protocol: collector.ProtocolICMP},
		{Protocol: collector.ProtocolTCP, SrcPort: 8080, DstPort: 9080},
	}
	collector.GetTraceFlows(recourses, server, ips, protocols)

	return nil
}
