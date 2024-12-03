package model

import (
	"errors"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)


func CreateAllTraceflows(resources *collector.ResourcesContainerModel, server collector.ServerData, ips []string, protocols []collector.TraceFlowProtocol) *collector.TraceFlows {
	traceFlows := collector.NewTraceflows(resources, server)
	for _, srcIP := range ips {
		for _, dstIP := range ips {
			for _, protocol := range protocols {
				if srcIP == dstIP {
					continue
				}
				traceFlows.AddTraceFlow(srcIP, dstIP, protocol)
			}
		}
	}
	return traceFlows
}


func verifyTraceflow(resources *collector.ResourcesContainerModel, server collector.ServerData) (*collector.TraceFlows, error) {
	config, err := configFromResourcesContainer(resources)
	if err != nil {
		return nil, err
	}
	ips := []string{}
	ipToVm := map[string]*endpoints.VM{}
	for uid, vm := range config.vmsMap {
		vmIps := resources.GetVirtualMachineAddresses(uid)
		// ips = append(ips, vmIps...) // todo
		if len(vmIps) > 0 {
			ips = append(ips, vmIps[0])
			ipToVm[vmIps[0]] = vm
		}
	}
	protocols := []collector.TraceFlowProtocol{
		{Protocol: collector.ProtocolICMP},
		{Protocol: collector.ProtocolTCP, SrcPort: 8080, DstPort: 9080},
	}
	traceFlows := CreateAllTraceflows(resources, server, ips, protocols)

	tfs := traceFlows.RunAndCollect()
	for _, tf := range tfs.Tfs{
		if tf.Name == ""{
			continue
		}
		srcVm := ipToVm[tf.Src]
		dstVm := ipToVm[tf.Dst]
		conn := config.analyzedConnectivity[srcVm][dstVm]
		switch tf.Protocol.Protocol{
		case collector.ProtocolICMP:
			if conn.ICMPSet().IsAll() != tf.Results.Delivered{
				tf.Errors = append(tf.Errors, "trace flow result is different from analyze result")
				err = errors.New("trace flow results is different from analyze results")
			}
		}
	}

	return tfs, err
}
