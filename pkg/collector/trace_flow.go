package collector

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	traceFlowsQuery              = "policy/api/v1/infra/traceflows"
	traceFlowQuery               = "policy/api/v1/infra/traceflows/%s"
	getTraceFlowObservationQuery = "policy/api/v1/infra/traceflows/%s/observations"
)

func traceFlowRandomID() string {
	rnd := make([]byte, 5)
	rand.Read(rnd)
	return fmt.Sprintf("traceFlow%X", rnd)

}

func traceFlow(resources *ResourcesContainerModel, server ServerData, srcIp, dstIp string) (string, error) {
	traceFlowName := traceFlowRandomID()
	srcVni := resources.GetVirtualNetworkInterfaceByAddress(srcIp)
	dstVni := resources.GetVirtualNetworkInterfaceByAddress(dstIp)

	if srcVni == nil {
		return "", fmt.Errorf("for traceflow, src %s must be a valid vni", srcIp)
	}
	srcMac := srcVni.MacAddress
	dstMac := srcMac
	if dstVni != nil {
		dstMac = dstVni.MacAddress
	}
	if srcVni.LportAttachmentId == nil {
		return "", fmt.Errorf("for traceflow, src %s must have port", srcIp)
	}
	port := resources.GetSegmentPort(*srcVni.LportAttachmentId)
	if port == nil {
		return "", fmt.Errorf("for traceflow, src %s must have port segment", srcIp)
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

func deleteTraceFlow(server ServerData, traceFlowName string) error {
	return DeleteResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName))
}

func collectTraceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	var t TraceFlowObservations
	err := collectResult(server, fmt.Sprintf(getTraceFlowObservationQuery, traceFlowName), &t)
	return t, err
}

func poolTraceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	for i := 0; i < 10; i++ {
		time.Sleep(3 * time.Second)
		t, err := collectTraceFlowObservation(server, traceFlowName)
		if err != nil {
			return nil, err
		}
		if t.completed() {
			return t, nil
		}
	}
	return nil, fmt.Errorf("trace flow is not completed")
}

//////////////////////////////////////////////////////////////////

type traceFlowKey struct {
	src, dst string
}
type traceFlows map[traceFlowKey]TraceFlowObservations

func getTraceFlows(resources *ResourcesContainerModel, server ServerData, ips []string) *traceFlows {
	tfNames := map[traceFlowKey]string{}
	for _, srcIp := range ips {
		for _, dstIp := range ips {
			key := traceFlowKey{srcIp, dstIp}
			if srcIp == dstIp {
				continue
			}
			if name, err := traceFlow(resources, server, srcIp, dstIp); err != nil {
				logging.Debug(err.Error())
			} else {
				tfNames[key] = name
			}
		}
	}
	traceFlows := traceFlows{}
	for key, name := range tfNames {
		if obs, err := poolTraceFlowObservation(server, name); err != nil {
			logging.Debug(err.Error())
		} else {
			traceFlows[key] = obs
		}
		if err := deleteTraceFlow(server, name); err != nil {
			logging.Debug(err.Error())
		}
	}
	return &traceFlows
}
func traceFlowsDotGraph(resources *ResourcesContainerModel, ips []string, traceFlows *traceFlows) *common.DotGraph{
	g := common.NewDotGraph(false)
	ipNodes := map[string]*observationNode{}
	for _, ip := range ips {
		ipNodes[ip] = &observationNode{ip: ip}
		vni := resources.GetVirtualNetworkInterfaceByAddress(ip)
		if vni != nil {
			ipNodes[ip].vmName = *resources.GetVirtualMachine(*vni.OwnerVmId).DisplayName
		}
	}
	for key, tf := range *traceFlows {
		observationNodes := tf.observationNodes(resources)
		lastObs := len(observationNodes) - 1
		g.AddEdge(ipNodes[key.src], observationNodes[0], nil)
		g.AddEdge(observationNodes[lastObs], ipNodes[key.dst], nil)
		for i := range observationNodes {
			if i != lastObs {
				g.AddEdge(observationNodes[i], observationNodes[i+1], nil)
			}
		}
	}
	return g
}
