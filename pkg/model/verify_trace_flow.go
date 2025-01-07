package model

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model/connectivity"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

type vmFilter func(vm *endpoints.VM) bool

func compareConfigToTraceflows(
	resources *collector.ResourcesContainerModel,
	server collector.ServerData,
	vmFilter vmFilter) (*collector.TraceFlows, error) {
	config, err := configFromResourcesContainer(resources, nil)
	if err != nil {
		return nil, err
	}
	traceFlows := createTraceflows(resources, server, config, vmFilter)
	traceFlows.Execute()
	traceFlows.Summary()
	return traceFlows, nil
}

func createTraceflows(resources *collector.ResourcesContainerModel,
	server collector.ServerData,
	config *config, vmFilter vmFilter) *collector.TraceFlows {
	traceFlows := collector.NewTraceflows(resources, server)
	for srcUID, srcVM := range config.vmsMap {
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
		for dstUID, dstVM := range config.vmsMap {
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
			//conn := config.analyzedConnectivity[srcVM][dstVM]
			// temp fix till analyze will consider topology:
			if !collector.IsVMConnected(resources, srcUID, dstUID) {
				continue
			}
			createTraceFlowsForConn(traceFlows, srcIP, dstIP, srcVM, dstVM, config.analyzedConnectivity)
		}
	}
	return traceFlows
}

func createTraceFlowsForConn(traceFlows *collector.TraceFlows, srcIP, dstIP string, srcVM, dstVM *endpoints.VM, connmap connectivity.ConnMap) {
	fmt.Printf("createTraceFlowsForConn: srcVM %s, dstVM: %s\n", srcVM.Name(), dstVM.Name())
	allowed, denied := connmap.GetDisjointExplanationsPerEndpoints(srcVM.Name(), dstVM.Name())
	for _, a := range allowed {
		createTraceFlowsForConnNewSingleExplain(traceFlows, srcIP, dstIP, a, true)
	}
	for _, d := range denied {
		createTraceFlowsForConnNewSingleExplain(traceFlows, srcIP, dstIP, d, false)
	}
}

func createTraceFlowsForConnNewSingleExplain(traceFlows *collector.TraceFlows, srcIP, dstIP string, connExplain *connectivity.DetailedConnection, isAllow bool) {
	ingressRules, egressRules := connExplain.ExplanationObj.RuleIDs()
	ingressRulesStr := common.JoinCustomStrFuncSlice(ingressRules, func(i int) string { return fmt.Sprintf("%d", i) }, ", ")
	egressRulesStr := common.JoinCustomStrFuncSlice(egressRules, func(i int) string { return fmt.Sprintf("%d", i) }, ", ")
	rulesConnString := fmt.Sprintf("conn: %s ingress rules: %s, egress rules: %s", connExplain.Conn.String(), ingressRulesStr, egressRulesStr)
	fmt.Printf("isAllow: %t, rulesConnString: %s\n", isAllow, rulesConnString)
	if !connExplain.Conn.TCPUDPSet().IsEmpty() {
		traceFlows.AddTraceFlow(srcIP, dstIP, toTCPTraceFlowProtocol(connExplain.Conn.TCPUDPSet()), isAllow, ingressRules, egressRules, rulesConnString)
	}
	if !connExplain.Conn.ICMPSet().IsEmpty() {
		//traceFlows.AddTraceFlow(srcIP, dstIP, collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP}, isAllow, ingressRules, egressRules, rulesConnString)
	}
}

/*func createTraceFlowsForConn(traceFlows *collector.TraceFlows, srcIP, dstIP string, dConn *connectivity.DetailedConnection) {
	conn := dConn.Conn
	connString := conn.String()
	if len(dConn.Explanation().Explanations()) == 0 {
		// one check only using icmp
		traceFlows.AddTraceFlow(srcIP, dstIP, collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP}, conn.IsAll(), 0, 0, connString)
		return
	}
	for _, explanation := range dConn.Explanation().Explanations() {
		rulesConnString := fmt.Sprintf("%s %d,%d", connString, explanation.EgressRule, explanation.IngressRule)
		if !explanation.Conn.TCPUDPSet().IsEmpty() {
			traceFlows.AddTraceFlow(srcIP, dstIP,
				toTCPTraceFlowProtocol(explanation.Conn.TCPUDPSet()),
				explanation.Allow, explanation.EgressRule, explanation.IngressRule, rulesConnString)
		}
		if !explanation.Conn.ICMPSet().IsEmpty() {
			traceFlows.AddTraceFlow(srcIP, dstIP,
				collector.TraceFlowProtocol{Protocol: collector.ProtocolICMP},
				explanation.Allow, explanation.EgressRule, explanation.IngressRule, rulesConnString)
		}
	}
}*/

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
