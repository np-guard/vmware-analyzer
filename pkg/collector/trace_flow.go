package collector

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	traceFlowsQuery              = "policy/api/v1/infra/traceflows"
	traceFlowQuery               = "policy/api/v1/infra/traceflows/%s"
	getTraceFlowObservationQuery = "policy/api/v1/infra/traceflows/%s/observations"
)

func traceFlow(resources *ResourcesContainerModel, server ServerData, srcIp, dstIp string) (string, error) {
	rnd := make([]byte, 5)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	traceFlowName := fmt.Sprintf("traceFlow%X", rnd)
	srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIp)
	dstVni := resources.GetVirtualNetworkInterfaceByAddress(dstIp)

	if srcVni == nil {
		return "", fmt.Errorf("src does not exist")
	}
	srcMac := srcVni.MacAddress
	dstMac := srcMac
	if dstVni != nil {
		dstMac = dstVni.MacAddress
		// return "", fmt.Errorf("dst does not exist")
	}
	if srcVni.LportAttachmentId == nil {
		return "", fmt.Errorf("src does not have port")
	}
	port := resources.GetSegmentPort(*srcVni.LportAttachmentId)
	if port == nil {
		return "", fmt.Errorf("src does not have port segment")
	}

	traceReq := &TraceflowConfig{}
	traceReq.SourceId = port.UniqueId
	traceReq.Packet = &nsx.FieldsPacketData{}
	traceReq.Packet.EthHeader = &nsx.EthernetHeader{SrcMac: srcMac, DstMac: dstMac}
	srcIPv4 := nsx.IPAddress(srcIp)
	dstIPv4 := nsx.IPAddress(dstIp)
	traceReq.Packet.IpHeader = &nsx.Ipv4Header{SrcIp: &srcIPv4, DstIp: &dstIPv4}
	traceReq.Packet.TransportHeader = &nsx.TransportProtocolHeader{}
	traceReq.Packet.TransportHeader.IcmpEchoRequestHeader = &nsx.IcmpEchoRequestHeader{}
	routed := bool(true)
	traceReq.Packet.Routed = &routed
	b, _ := json.Marshal(traceReq)
	json.Unmarshal(b, &traceReq)
	PutResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName), traceReq)
	return traceFlowName, nil
}

func deleteAllTraceFlows(server ServerData) error {
	ts := []nsx.TraceflowConfig{}
	err := collectResultList(server, traceFlowsQuery, &ts)
	if err != nil {
		return err
	}
	for i := range ts {
		traceFlowName := *ts[i].Id
		err := deleteTraceFlow(server, traceFlowName)
		if err != nil {
			return err
		}
	}
	return nil
}
func deleteTraceFlow(server ServerData, traceFlowName string) error {
	return DeleteResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName))
}

func traceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	var t TraceFlowObservations
	err := collectResult(server, fmt.Sprintf(getTraceFlowObservationQuery, traceFlowName), &t)
	return t, err
}

func poolTraceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	for i := 0; i < 10; i++ {
		time.Sleep(3 * time.Second)
		t, err := traceFlowObservation(server, traceFlowName)
		if err != nil {
			return nil, err
		}
		if len(t) > 0 {
			return t, nil
		}
	}
	return nil, fmt.Errorf("trace flow has zero observations")
}

func traceFlowsGraph(resources *ResourcesContainerModel, server ServerData, ips []string) {
	tfNames := map[string]string{}
	tfObservation := map[string]TraceFlowObservations{}
	for _, srcIp := range ips {
		for _, dstIp := range ips {
			key := fmt.Sprintf("%s:%s", srcIp, dstIp)
			if srcIp == dstIp {
				continue
			}
			if name, err := traceFlow(resources, server, srcIp, dstIp); err != nil {
				// tfObservation[key] += fmt.Sprintf("poolTraceFlowObservation() error = %v", err)
			} else {
				tfNames[key] = name
			}
		}
	}
	for _, srcIp := range ips {
		for _, dstIp := range ips {
			key := fmt.Sprintf("%s:%s", srcIp, dstIp)
			if srcIp == dstIp || tfNames[key] == "" {
				continue
			}
			if obs, err := poolTraceFlowObservation(server, tfNames[key]); err != nil {
				// tfObservation[key] += fmt.Sprintf("poolTraceFlowObservation() error = %v", err)
			} else {
				tfObservation[key] = obs
			}
			if err := deleteTraceFlow(server, tfNames[key]); err != nil {
				// tfObservation[key] += fmt.Sprintf("deleteTraceFlow() error = %v", err)
			}
		}
	}
	g := common.NewDotGraph(false)
	ipNodes := make([]*observationNode, len(ips))
	for i, ip := range ips {
		ipNodes[i] = &observationNode{ip: ip}
		vni := resources.GetVirtualNetworkInterfaceByAddress(ip)
		if vni != nil {
			ipNodes[i].vmName = *resources.GetVirtualMachine(*vni.OwnerVmId).DisplayName
		}
	}
	for _, srcIp := range ipNodes {
		for _, dstIp := range ipNodes {
			key := fmt.Sprintf("%s:%s", srcIp.ip, dstIp.ip)
			if srcIp == dstIp || tfObservation[key] == nil {
				continue
			}
			observationNodes := tfObservation[key].observationNodes(resources)
			lastObs := len(observationNodes) - 1
			g.AddEdge(srcIp, observationNodes[0], nil)
			g.AddEdge(observationNodes[lastObs], dstIp, nil)
			for i := range observationNodes {
				if i != lastObs {
					g.AddEdge(observationNodes[i], observationNodes[i+1], nil)
				}
			}
		}
	}
	common.OutputGraph(g, "out/traceflow.dot", common.DotFormat)
}
