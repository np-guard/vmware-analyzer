package analyzer

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/analyzer/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

type vmFilter func(vm topology.Endpoint) bool

func compareConfigToTraceflows(
	resources *collector.ResourcesContainerModel,
	server collector.ServerData,
	vmFilter vmFilter) (*collector.TraceFlows, error) {
	config, connMap, _, err := NSXConnectivityFromResourcesContainer(resources, common.OutputParameters{})
	if err != nil {
		return nil, err
	}

	traceFlows := createTraceflows(resources, server, config, connMap, vmFilter)
	traceFlows.Execute()
	traceFlows.Summary()
	return traceFlows, nil
}

func createTraceflows(resources *collector.ResourcesContainerModel,
	server collector.ServerData,
	config *configuration.Config, connMap connectivity.ConnMap, vmFilter vmFilter) *collector.TraceFlows {
	traceFlows := collector.NewTraceflows(resources, server)
	for srcUID, srcVM := range config.VMsMap {
		if !vmFilter(srcVM) {
			continue
		}
		vmIPs := resources.GetVirtualMachineAddresses(srcUID)
		if len(vmIPs) == 0 {
			continue
		}
		srcIP := vmIPs[0]
		srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIP)
		if srcVni == nil {
			continue
		}
		port := resources.GetSegmentPort(*srcVni.LportAttachmentId)
		if port == nil {
			continue
		}
		for dstUID, dstVM := range config.VMsMap {
			if srcUID == dstUID {
				continue
			}
			if !vmFilter(dstVM) {
				continue
			}
			vmIPs := resources.GetVirtualMachineAddresses(dstUID)
			if len(vmIPs) == 0 {
				continue
			}
			dstIP := vmIPs[0]
			// conn := config.analyzedConnectivity[srcVM][dstVM]
			// temp fix till analyze will consider topology:
			if !collector.IsVMConnected(resources, srcUID, dstUID) {
				continue
			}
			createTraceFlowsForConn(traceFlows, srcIP, dstIP, srcVM, dstVM, connMap)
		}
	}
	return traceFlows
}

func createTraceFlowsForConn(traceFlows *collector.TraceFlows, srcIP, dstIP string,
	srcVM, dstVM topology.Endpoint, connmap connectivity.ConnMap) {
	fmt.Printf("createTraceFlowsForConn: srcVM %s, dstVM: %s\n", srcVM.Name(), dstVM.Name())
	allowed, denied := connmap.GetDisjointExplanationsPerEndpoints(srcVM.Name(), dstVM.Name())
	for _, a := range allowed {
		createTraceFlowsForConnNewSingleExplain(traceFlows, srcIP, dstIP, a, true)
	}
	for _, d := range denied {
		createTraceFlowsForConnNewSingleExplain(traceFlows, srcIP, dstIP, d, false)
	}
}

func createTraceFlowsForConnNewSingleExplain(traceFlows *collector.TraceFlows, srcIP, dstIP string,
	connExplain *connectivity.DetailedConnection, isAllow bool) {
	ingressRules, egressRules := connExplain.ExplanationObj.RuleIDs()
	var intToStr = func(i int) string { return fmt.Sprintf("%d", i) }
	ingressRulesStr := common.JoinCustomStrFuncSlice(ingressRules, intToStr, common.CommaSpaceSeparator)
	egressRulesStr := common.JoinCustomStrFuncSlice(egressRules, intToStr, common.CommaSpaceSeparator)
	rulesConnString := fmt.Sprintf("conn: %s ingress rules: %s, egress rules: %s", connExplain.Conn.String(), ingressRulesStr, egressRulesStr)
	fmt.Printf("isAllow: %t, rulesConnString: %s\n", isAllow, rulesConnString)
	if !connExplain.Conn.TCPUDPSet().IsEmpty() {
		traceFlows.AddTraceFlow(srcIP, dstIP,
			toTCPTraceFlowProtocol(connExplain.Conn.TCPUDPSet()), isAllow, ingressRules, egressRules, rulesConnString)
	}
	if !connExplain.Conn.ICMPSet().IsEmpty() {
		traceFlows.AddTraceFlow(srcIP, dstIP,
			collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP}, isAllow, ingressRules, egressRules, rulesConnString)
	}
}

func toTCPTraceFlowProtocol(set *netset.TCPUDPSet) collector.TraceFlowProtocol {
	partition := set.Partitions()[0]
	protocol := collector.ProtocolUDP
	if partition.S1.Contains(netset.TCPCode) {
		protocol = collector.ProtocolTCP
	}
	srcPort := partition.S2.Min()
	dstPort := partition.S3.Min()
	return collector.TraceFlowProtocol{Protocol: protocol, SrcPort: int(srcPort), DstPort: int(dstPort)}
}
