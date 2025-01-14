package synthesis

import (
	"fmt"
	"path"
	"slices"

	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

const k8sAPIVersion = "networking.k8s.io/v1"

func CreateK8sResources(model *AbstractModelSyn, outDir string) error {
	policies := toNetworkPolicies(model)
	policiesFileName := path.Join(outDir, "policies.yaml")
	if err := common.WriteYamlUsingJSON(policies, policiesFileName); err != nil {
		return err
	}
	pods := toPods(model)
	podsFileName := path.Join(outDir, "pods.yaml")
	if err := common.WriteYamlUsingJSON(pods, podsFileName); err != nil {
		return err
	}
	for _, format := range []string{"txt", "dot"} {
		out, err := k8sAnalyzer(outDir, format)
		if err != nil {
			return err
		}
		err = common.WriteToFile(path.Join(outDir, "k8s_connectivity."+format), out)
		if err != nil {
			return err
		}
	}
	return nil
}

func toNetworkPolicies(model *AbstractModelSyn) []*networking.NetworkPolicy {
	policies := []*networking.NetworkPolicy{}
	addNewPolicy := func(description string) *networking.NetworkPolicy {
		pol := newNetworkPolicy(fmt.Sprintf("policy_%d", len(policies)), description)
		policies = append(policies, pol)
		return pol
	}
	for _, p := range model.policy {
		for _, ob := range p.outbound {
			for _, p := range ob.allowOnlyRulePaths {
				srcSelector, dstSelector, ports, empty := toSelectorsAndPorts(p)
				if empty {
					continue
				}
				to := []networking.NetworkPolicyPeer{{PodSelector: dstSelector}}
				rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports}}
				pol := addNewPolicy(p.String())
				pol.Spec.Egress = rules
				pol.Spec.PolicyTypes = []networking.PolicyType{"Egress"}
				pol.Spec.PodSelector = *srcSelector
			}
		}
		for _, ib := range p.inbound {
			for _, p := range ib.allowOnlyRulePaths {
				srcSelector, dstSelector, ports, empty := toSelectorsAndPorts(p)
				if empty {
					continue
				}
				from := []networking.NetworkPolicyPeer{{PodSelector: srcSelector}}
				rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports}}
				pol := addNewPolicy(p.String())
				pol.Spec.Ingress = rules
				pol.Spec.PolicyTypes = []networking.PolicyType{"Ingress"}
				pol.Spec.PodSelector = *dstSelector
			}
		}
	}
	return policies
}

func newNetworkPolicy(name, description string) *networking.NetworkPolicy {
	pol := &networking.NetworkPolicy{}
	pol.TypeMeta.Kind = "NetworkPolicy"
	pol.TypeMeta.APIVersion = k8sAPIVersion
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{"description": description}
	return pol
}

func toSelectorsAndPorts(p *symbolicexpr.SymbolicPath) (srcSelector, dstSelector *meta.LabelSelector,
	ports []networking.NetworkPolicyPort, empty bool) {
	srcSelector = toSelector(p.Src)
	dstSelector = toSelector(p.Dst)
	ports, empty = toPolicyPorts(p.Conn)
	return
}

var codeToProtocol = map[int]core.Protocol{netset.UDPCode: core.ProtocolUDP, netset.TCPCode: core.ProtocolTCP}
var boolToOperator = map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}

func pointerTo[T any](t T) *T {
	return &t
}

func toSelector(con symbolicexpr.Conjunction) *meta.LabelSelector {
	selector := &meta.LabelSelector{}
	for _, a := range con {
		label, notIn := a.AsSelector()
		if label != "" { // not tautology
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}

func toPolicyPorts(conn *netset.TransportSet) ([]networking.NetworkPolicyPort, bool) {
	ports := []networking.NetworkPolicyPort{}
	tcpUDPSet := conn.TCPUDPSet()
	if tcpUDPSet.IsEmpty() {
		return nil, true
	}
	if tcpUDPSet.IsAll() {
		return nil, false
	}
	partitions := tcpUDPSet.Partitions()
	for _, partition := range partitions {
		protocols := partition.S1.Elements()
		portRanges := partition.S3
		for _, portRange := range portRanges.Intervals() {
			var portPointer *intstr.IntOrString
			var endPortPointer *int32
			if portRange.Start() != netp.MinPort || portRange.End() != netp.MaxPort {
				port := intstr.FromInt(int(portRange.Start()))
				portPointer = &port
				if portRange.End() != portRange.Start() {
					//nolint:gosec // port should fit int32:
					endPort := int32(portRange.End())
					endPortPointer = &endPort
				}
			}
			for _, protocolCode := range protocols {
				ports = append(ports, networking.NetworkPolicyPort{
					Protocol: pointerTo(codeToProtocol[int(protocolCode)]),
					Port:     portPointer,
					EndPort:  endPortPointer})
			}
			if slices.Contains(protocols, netset.TCPCode) && slices.Contains(protocols, netset.UDPCode) {
				ports = append(ports, networking.NetworkPolicyPort{Protocol: pointerTo(core.ProtocolSCTP), Port: portPointer, EndPort: endPortPointer})
			}
		}
	}
	return ports, false
}

// ///////////////////////////////////////////////////////////////////////////////
func toPods(model *AbstractModelSyn) []*core.Pod {
	pods := []*core.Pod{}
	for _, vm := range model.vms {
		pod := &core.Pod{}
		pod.TypeMeta.Kind = "Pod"
		pod.TypeMeta.APIVersion = k8sAPIVersion
		pod.ObjectMeta.Name = vm.Name()
		pod.ObjectMeta.UID = types.UID(vm.ID())
		if len(model.epToGroups[vm]) == 0 {
			continue
		}
		pod.ObjectMeta.Labels = map[string]string{}
		for _, group := range model.epToGroups[vm] {
			label, _ := symbolicexpr.NewAtomicTerm(group, group.Name(), false).AsSelector()
			pod.ObjectMeta.Labels[label] = "true"
		}
		pods = append(pods, pod)
	}
	return pods
}

///////////////////////////////////////////////////////////////////////////

func k8sAnalyzer(outDir, format string) (string, error) {
	analyzer := connlist.NewConnlistAnalyzer(connlist.WithOutputFormat(format))

	conns, _, err := analyzer.ConnlistFromDirPath(outDir)
	if err != nil {
		return "", err
	}
	return analyzer.ConnectionsListToString(conns)
}
