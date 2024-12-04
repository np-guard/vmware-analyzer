package collector

import (
	crypto_rand "crypto/rand"
	"encoding/json"
	"fmt"
	math_rand "math/rand"
	"time"

	"github.com/np-guard/vmware-analyzer/pkg/logging"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	traceFlowsQuery              = "policy/api/v1/infra/traceflows"
	traceFlowQuery               = "policy/api/v1/infra/traceflows/%s"
	getTraceFlowObservationQuery = "policy/api/v1/infra/traceflows/%s/observations"
)
const (
	ProtocolTCP   = "tcp"
	ProtocolUDP   = "udp"
	ProtocolICMP  = "icmp"
	TCPFlagSYN    = 2
	maxTraceFlows = 128
)

const (
	traceflowIDSize          = 5
	traceflowPoolingTime     = 3 * time.Second
	traceflowCreationTime    = time.Second
	traceflowNumberOfPooling = 10
)

type traceFlow struct {
	Src          string                `json:"src,omitempty"`
	Dst          string                `json:"dst,omitempty"`
	SrcVM        string                `json:"src_vm,omitempty"`
	DstVM        string                `json:"dst_vm,omitempty"`
	Protocol     TraceFlowProtocol     `json:"protocol,omitempty"`
	Name         string                `json:"name,omitempty"`
	Errors       []string              `json:"errors,omitempty"`
	Results      traceflowResult       `json:"results,omitempty"`
	Allowed      bool                  `json:"allowed,omitempty"`
	Observations TraceFlowObservations `json:"observation,omitempty"`
}

type TraceFlowProtocol struct {
	SrcPort  int    `json:"src_port,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

func (t *TraceFlowProtocol) header() *nsx.TransportProtocolHeader {
	h := &nsx.TransportProtocolHeader{}
	switch t.Protocol {
	case ProtocolTCP:
		flags := TCPFlagSYN
		h.TcpHeader = &nsx.TcpHeader{SrcPort: &t.SrcPort, DstPort: &t.DstPort, TcpFlags: &flags}
	case ProtocolUDP:
		h.UdpHeader = &nsx.UdpHeader{SrcPort: t.SrcPort, DstPort: t.DstPort}
	case ProtocolICMP:
		h.IcmpEchoRequestHeader = &nsx.IcmpEchoRequestHeader{}
	}
	return h
}

type TraceFlows struct {
	Tfs       []*traceFlow
	resources *ResourcesContainerModel
	server    ServerData
}

func NewTraceflows(resources *ResourcesContainerModel, server ServerData) *TraceFlows {
	return &TraceFlows{resources: resources, server: server}
}
func (tfs *TraceFlows) AddTraceFlow(src, dst string, protocol TraceFlowProtocol, allowed bool) {
	tfs.Tfs = append(tfs.Tfs, &traceFlow{Src: src, Dst: dst, Protocol: protocol, Allowed: allowed})
}

// ToJSONString converts a traceFlows into a json-formatted-string
func (tfs *TraceFlows) ToJSONString() (string, error) {
	toPrint, err := json.MarshalIndent(tfs.Tfs, "", "    ")
	return string(toPrint), err
}

func (traceFlows *TraceFlows) RunAndCollect() *TraceFlows {
	traceFlows.runTracflows()
	traceFlows.collectTracflowsData()
	return traceFlows
}
func (traceFlows *TraceFlows) runTracflows() {
	for _, traceFlow := range traceFlows.Tfs {
		if len(traceFlows.Tfs) > maxTraceFlows && math_rand.Intn(len(traceFlows.Tfs)) > maxTraceFlows {
			continue
		}
		if name, err := traceFlow.run(traceFlows.resources, traceFlows.server); err != nil {
			logging.Debug(err.Error())
			traceFlow.Errors = append(traceFlow.Errors, err.Error())
		} else {
			traceFlow.Name = name
		}
		time.Sleep(traceflowCreationTime)
	}
}
func (traceFlows *TraceFlows) collectTracflowsData() {
	time.Sleep(traceflowPoolingTime)
	for _, traceFlow := range traceFlows.Tfs {
		if traceFlow.Name == "" || len(traceFlow.Errors) > 0 {
			continue
		}
		if obs, err := poolTraceFlowObservation(traceFlows.server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
			traceFlow.Errors = append(traceFlow.Errors, err.Error())
		} else {
			traceFlow.Observations = obs
		}
		if err := deleteTraceFlow(traceFlows.server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
			traceFlow.Errors = append(traceFlow.Errors, err.Error())
		}
		traceFlow.Results = traceFlow.Observations.results()
		if traceFlow.Allowed != traceFlow.Results.Delivered {
			traceFlow.Errors = append(traceFlow.Errors, "trace flow result is different from analyze result")
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////

func traceFlowRandomID() (string, error) {
	rnd := make([]byte, traceflowIDSize)
	if _, err := crypto_rand.Read(rnd); err != nil {
		return "", err
	}
	return fmt.Sprintf("traceFlow%X", rnd), nil
}

func (tf *traceFlow) run(resources *ResourcesContainerModel, server ServerData) (string, error) {
	traceFlowName, err := traceFlowRandomID()
	if err != nil {
		return "", err
	}
	srcVni := resources.GetVirtualNetworkInterfaceByAddress(tf.Src)
	dstVni := resources.GetVirtualNetworkInterfaceByAddress(tf.Dst)

	if srcVni == nil {
		return "", fmt.Errorf("for traceflow, src %s must be a valid vni", tf.Src)
	}
	tf.SrcVM = *resources.GetVirtualMachine(*srcVni.OwnerVmId).DisplayName

	srcMac := srcVni.MacAddress
	dstMac := srcMac
	if dstVni != nil {
		dstMac = dstVni.MacAddress
		tf.DstVM = *resources.GetVirtualMachine(*dstVni.OwnerVmId).DisplayName
	}
	if srcVni.LportAttachmentId == nil {
		return "", fmt.Errorf("for traceflow, src %s must have port", tf.Src)
	}
	port := resources.GetSegmentPort(*srcVni.LportAttachmentId)
	if port == nil {
		return "", fmt.Errorf("for traceflow, src %s must have port segment", tf.Src)
	}

	traceReq := &TraceflowConfig{}
	traceReq.SourceID = port.UniqueId
	traceReq.Packet = &nsx.FieldsPacketData{}
	traceReq.Packet.EthHeader = &nsx.EthernetHeader{SrcMac: srcMac, DstMac: dstMac}
	srcIPv4 := nsx.IPAddress(tf.Src)
	dstIPv4 := nsx.IPAddress(tf.Dst)
	traceReq.Packet.IpHeader = &nsx.Ipv4Header{SrcIp: &srcIPv4, DstIp: &dstIPv4}
	traceReq.Packet.TransportHeader = tf.Protocol.header()
	routed := bool(true)
	traceReq.Packet.Routed = &routed

	b, err := json.Marshal(traceReq)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(b, &traceReq)
	if err != nil {
		return "", err
	}
	err = PutResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName), traceReq)
	if err != nil {
		return "", err
	}
	return traceFlowName, nil
}

/////////////////////////////////////////////////////////

func deleteTraceFlow(server ServerData, traceFlowName string) error {
	return DeleteResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName))
}

func collectTraceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	var t TraceFlowObservations
	err := collectResult(server, fmt.Sprintf(getTraceFlowObservationQuery, traceFlowName), &t)
	return t, err
}

func poolTraceFlowObservation(server ServerData, traceFlowName string) (TraceFlowObservations, error) {
	for i := 0; i < traceflowNumberOfPooling; i++ {
		t, err := collectTraceFlowObservation(server, traceFlowName)
		if err != nil {
			return nil, err
		}
		if t.completed() {
			return t, nil
		}
		time.Sleep(traceflowPoolingTime)
	}
	return nil, fmt.Errorf("trace flow is not completed")
}

//////////////////////////////////////////////////////////////////
