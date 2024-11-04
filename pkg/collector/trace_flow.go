package collector

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	traceFlowQuery               = "policy/api/v1/infra/traceflows/%s"
	getTraceFlowObservationQuery = "policy/api/v1/infra/traceflows/%s/observations"
)

func traceFlow(resources *ResourcesContainerModel, server ServerData) (string, error) {
	srcIp := "192.168.1.1"
	dstIp := "192.168.1.2"
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
	if dstVni == nil {
		return "", fmt.Errorf("dst does not exist")
	}
	if srcVni.LportAttachmentId == nil {
		return "", fmt.Errorf("src does not have port")
	}
	port := resources.GetSegmentPort(*srcVni.LportAttachmentId)

	traceReq := &TraceflowConfig{}
	traceReq.SourceId = port.UniqueId
	traceReq.Packet = &nsx.FieldsPacketData{}
	traceReq.Packet.EthHeader = &nsx.EthernetHeader{SrcMac: srcVni.MacAddress, DstMac: dstVni.MacAddress}
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
		time.Sleep(3*time.Second)
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
