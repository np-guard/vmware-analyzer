package collector

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/np-guard/vmware-analyzer/internal/common"
	nsx "github.com/np-guard/vmware-analyzer/pkg/analyzer/generated"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
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

// ///////////////////////////////////////////////////////////////////////////////
type analyzeResults struct {
	Allow     bool  `json:"allowed"`
	SrcRuleID []int `json:"src_rule_id,omitempty"`
	DstRuleID []int `json:"dst_rule_id,omitempty"`
}

type traceFlow struct {
	Src            string                `json:"src,omitempty"`
	Dst            string                `json:"dst,omitempty"`
	SrcVM          string                `json:"src_vm,omitempty"`
	DstVM          string                `json:"dst_vm,omitempty"`
	Protocol       TraceFlowProtocol     `json:"protocol,omitempty"`
	NotSent        bool                  `json:"not_sent,omitempty"`
	Name           string                `json:"name,omitempty"`
	APIErrors      []string              `json:"api_errors,omitempty"`
	Errors         []string              `json:"errors,omitempty"`
	Results        traceflowResult       `json:"results,omitempty"`
	AnalyzeResults analyzeResults        `json:"analyze_results"`
	Connection     string                `json:"connection,omitempty"`
	Observations   TraceFlowObservations `json:"observation,omitempty"`
}

func (tf *traceFlow) send(resources *ResourcesContainerModel, server ServerData) (string, error) {
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
	err = putTraceFlow(server, traceFlowName, traceReq)
	if err != nil {
		return "", err
	}
	return traceFlowName, nil
}

// //////////////////////////////////////////////////////////////////////////////////////////////
type TraceFlows struct {
	Tfs       []*traceFlow
	resources *ResourcesContainerModel
	server    ServerData
}

func NewTraceflows(resources *ResourcesContainerModel, server ServerData) *TraceFlows {
	return &TraceFlows{resources: resources, server: server}
}
func (traceFlows *TraceFlows) AddTraceFlow(src, dst string, protocol TraceFlowProtocol,
	analyzeAllowed bool, srcRuleID, dstRuleID []int, connection string) {
	traceFlows.Tfs = append(traceFlows.Tfs,
		&traceFlow{Src: src, Dst: dst, Protocol: protocol,
			AnalyzeResults: analyzeResults{analyzeAllowed, srcRuleID, dstRuleID},
			Connection:     connection})
}

// ToJSONString converts a traceFlows into a json-formatted-string, it converts only the Tfs
func (traceFlows *TraceFlows) ToJSONString() (string, error) {
	return common.MarshalJSON(traceFlows.Tfs)
}

func (traceFlows *TraceFlows) Execute() {
	traceFlows.sendTraceflows()
	traceFlows.collectTracflowsData()
}

func (traceFlows *TraceFlows) sendTraceflows() {
	for _, traceFlow := range traceFlows.Tfs {
		randomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(len(traceFlows.Tfs))))
		if err != nil {
			traceFlow.APIErrors = append(traceFlow.APIErrors, err.Error())
			logging.Debug(err.Error())
			continue
		}
		if len(traceFlows.Tfs) > maxTraceFlows && randomNumber.Int64() > maxTraceFlows {
			traceFlow.NotSent = true
			continue
		}
		if name, err := traceFlow.send(traceFlows.resources, traceFlows.server); err != nil {
			logging.Debug(err.Error())
			traceFlow.APIErrors = append(traceFlow.APIErrors, err.Error())
		} else {
			traceFlow.Name = name
		}
		time.Sleep(traceflowCreationTime)
	}
}

func ruleIDsAsStrings(ids []int) []string {
	return common.CustomStrSliceToStrings(ids, func(i int) string { return fmt.Sprintf("%d", i) })
}

func (traceFlows *TraceFlows) collectTracflowsData() {
	time.Sleep(traceflowPoolingTime)
	for _, traceFlow := range traceFlows.Tfs {
		if traceFlow.Name == "" || len(traceFlow.APIErrors) > 0 {
			continue
		}
		if obs, err := poolTraceFlowObservation(traceFlows.server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
			traceFlow.APIErrors = append(traceFlow.APIErrors, err.Error())
		} else {
			traceFlow.Observations = obs
		}
		if err := deleteTraceFlow(traceFlows.server, traceFlow.Name); err != nil {
			logging.Debug(err.Error())
			traceFlow.APIErrors = append(traceFlow.APIErrors, err.Error())
		}
		traceFlow.Results = traceFlow.Observations.results()
		if traceFlow.Results.Completed {
			analyzeSrcRuleIDs := ruleIDsAsStrings(traceFlow.AnalyzeResults.SrcRuleID)
			analyzeDstRuleIDs := ruleIDsAsStrings(traceFlow.AnalyzeResults.DstRuleID)
			switch {
			case traceFlow.AnalyzeResults.Allow != traceFlow.Results.Delivered:
				traceFlow.Errors = append(traceFlow.Errors, "trace flow result is different from analyze result")

			case !slices.Contains(analyzeSrcRuleIDs, traceFlow.Results.SrcRuleID):
				traceFlow.Errors = append(traceFlow.Errors, "analyze egress rule is different from trace flow egress rule")

			case traceFlow.Results.DstRuleID != "" && !slices.Contains(analyzeDstRuleIDs, traceFlow.Results.DstRuleID):
				traceFlow.Errors = append(traceFlow.Errors, "analyze ingress rule is different from trace flow ingress rule")

				// TODO: consider this case?
				/*case traceFlow.Results.DstRuleID == "" && analyzeDstRuleID != "0" && analyzeDstRuleID != traceFlow.Results.SrcRuleID:
				traceFlow.Errors = append(traceFlow.Errors, "trace flow ingress rule is missing,"+
					" and analyze ingress rule rule different from trace flow egress")*/
			}
		}
	}
}

func (traceFlows *TraceFlows) Summary() {
	var notSent, withAPIErrors, withResultErrors, withError, falseAllow, falseDeny int
	var apiErrors, resultErrors, errors []string
	for _, traceFlow := range traceFlows.Tfs {
		if traceFlow.NotSent {
			notSent++
		}
		if len(traceFlow.Errors) > 0 {
			withError++
			errors = append(errors, traceFlow.Errors...)
		}
		if len(traceFlow.APIErrors) > 0 {
			withAPIErrors++
			apiErrors = append(apiErrors, traceFlow.APIErrors...)
		}
		if len(traceFlow.Results.Errors) > 0 {
			withResultErrors++
			resultErrors = append(resultErrors, traceFlow.Results.Errors...)
		}
		if traceFlow.Results.Completed && traceFlow.Results.Delivered && !traceFlow.AnalyzeResults.Allow {
			falseDeny++
		}
		if traceFlow.Results.Completed && !traceFlow.Results.Delivered && traceFlow.AnalyzeResults.Allow {
			falseAllow++
		}
	}
	slices.Sort(errors)
	slices.Sort(apiErrors)
	slices.Sort(resultErrors)
	errors = slices.Compact(errors)
	apiErrors = slices.Compact(apiErrors)
	resultErrors = slices.Compact(resultErrors)
	fmt.Println("traceflow summary:")
	fmt.Printf("N of traceflow sent: %d, out of %d\n", len(traceFlows.Tfs)-notSent, len(traceFlows.Tfs))
	fmt.Printf("N of traceflow with errors: %d\n", withError)
	fmt.Printf("N of false allow: %d\n", falseAllow)
	fmt.Printf("N of false deny:  %d\n", falseDeny)
	fmt.Printf("N of traceflow with api errors: %d\n", withAPIErrors)
	fmt.Printf("N of traceflow with result parsing errors: %d\n", withResultErrors)
	fmt.Printf("traceflow errors:\n %s\n\n", strings.Join(errors, "\n"))
	fmt.Printf("traceflow api errors:\n %s\n\n", strings.Join(apiErrors, "\n"))
	fmt.Printf("traceflow result errors:\n %s\n\n", strings.Join(resultErrors, "\n"))
}

// //////////////////////////////////////////////////////////////////////////////////////////////
func traceFlowRandomID() (string, error) {
	rnd := make([]byte, traceflowIDSize)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	return fmt.Sprintf("traceFlow%X", rnd), nil
}

func putTraceFlow(server ServerData, traceFlowName string, traceReq *TraceflowConfig) error {
	return PutResource(server, fmt.Sprintf(traceFlowQuery, traceFlowName), traceReq)
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
