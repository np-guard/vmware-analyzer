package model

import (
	"strings"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type vmFilter func(vm *endpoints.VM) bool

func createRelevantTraceflows(resources *collector.ResourcesContainerModel, server collector.ServerData, config *config, vmFilter vmFilter) *collector.TraceFlows {

	traceFlows := collector.NewTraceflows(resources, server)
	for srcUid, srcVm := range config.vmsMap {
		if !vmFilter(srcVm) {
			continue
		}
		vmIps := resources.GetVirtualMachineAddresses(srcUid)
		if len(vmIps) == 0 {
			continue
		}
		srcIP := vmIps[0]
		for dstUid, dstVm := range config.vmsMap {
			if srcUid == dstUid {
				continue
			}
			if !vmFilter(dstVm) {
				continue
			}
			vmIps := resources.GetVirtualMachineAddresses(dstUid)
			if len(vmIps) == 0 {
				continue
			}
			dstIP := vmIps[0]
			conn := config.analyzedConnectivity[srcVm][dstVm]
			connString := conn.String()
			switch {
			case conn.IsAll(), conn.IsEmpty():
				// one check only using icmp
				traceFlows.AddTraceFlow(srcIP, dstIP, collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP}, conn.IsAll(), connString)


			case conn.TCPUDPSet().IsAll() || conn.TCPUDPSet().IsEmpty():
				// one check for icmp, one for tcp/udp
				traceFlows.AddTraceFlow(srcIP, dstIP, collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP}, conn.ICMPSet().IsAll(), connString)
				aPort := (netp.MaxPort + netp.MinPort) / 2
				defaultProtocol := collector.TraceFlowProtocol{Protocol: collector.ProtocolTCP, SrcPort: aPort, DstPort: aPort}
				traceFlows.AddTraceFlow(srcIP, dstIP, defaultProtocol, conn.TCPUDPSet().IsAll(), connString)
			default:
				// checking only tcp/udp, one allow, one deny
				allowConn := conn.TCPUDPSet()
				denyConn := netset.AllTCPUDPSet().Subtract(allowConn)
				traceFlows.AddTraceFlow(srcIP, dstIP, toTraceFlowProtocol(allowConn), true, connString)
				traceFlows.AddTraceFlow(srcIP, dstIP, toTraceFlowProtocol(denyConn), false, connString)
			}
		}
	}
	return traceFlows
}

func toTraceFlowProtocol(set *netset.TCPUDPSet) collector.TraceFlowProtocol {
	partition := set.Partitions()[0]
	protocol := collector.ProtocolUDP
	if partition.S1.Contains(netset.TCPCode) {
		protocol = collector.ProtocolTCP
	}
	srcPort := partition.S2.Min()
	dstPort := partition.S3.Min()
	return collector.TraceFlowProtocol{Protocol: protocol, SrcPort: int(srcPort), DstPort: int(dstPort)}
}

func verifyTraceflow(resources *collector.ResourcesContainerModel, server collector.ServerData) (*collector.TraceFlows, error) {
	config, err := configFromResourcesContainer(resources,nil)
	if err != nil {
		return nil, err
	}
	traceFlows := createRelevantTraceflows(resources, server, config, func(vm *endpoints.VM) bool { return strings.Contains(vm.Name(), "New") })

	tfs := traceFlows.RunAndCollect()

	return tfs, nil
}
