package synthesis

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

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
		out, err := listConn(outDir, format)
		if err != nil {
			return err
		}
		out = strings.ReplaceAll(out, "[Pod]", "")
		out = strings.ReplaceAll(out, "default/", "")
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
				srcSelector := conjunctionToSelector(p.Src)
				dstSelector := conjunctionToSelector(p.Dst)
				ports := toPolicyPorts(p.Conn)
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
				srcSelector := conjunctionToSelector(p.Src)
				dstSelector := conjunctionToSelector(p.Dst)
				ports := toPolicyPorts(p.Conn)
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
	pol.TypeMeta.APIVersion = "networking.k8s.io/v1"
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Labels = map[string]string{"description": description}
	return pol
}

var codeToProtocol = map[int]core.Protocol{netset.UDPCode: core.ProtocolUDP, netset.TCPCode: core.ProtocolTCP}
var boolToOperator = map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}

func pointerTo[T any](t T) *T {
	return &t
}

func conjunctionToSelector(con symbolicexpr.Conjunction) *meta.LabelSelector {
	selector := &meta.LabelSelector{}
	for _, a := range con {
		label, notIn := a.AsSelector()
		if label != "" { // tautology
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}

func toPolicyPorts(conn *netset.TransportSet) []networking.NetworkPolicyPort {

	ports := []networking.NetworkPolicyPort{}
	tcpUdpSet := conn.TCPUDPSet()
	if tcpUdpSet.IsAll() {
		return nil
	} else {
		partitions := tcpUdpSet.Partitions()
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
						endPort := int32(portRange.End())
						endPortPointer = &endPort
					}
				}
				for _, protocolCode := range protocols {
					ports = append(ports, networking.NetworkPolicyPort{Protocol: pointerTo(codeToProtocol[int(protocolCode)]), Port: portPointer, EndPort: endPortPointer})
				}
				if slices.Contains(protocols, netset.TCPCode) && slices.Contains(protocols, netset.UDPCode) {
					ports = append(ports, networking.NetworkPolicyPort{Protocol: pointerTo(core.ProtocolSCTP), Port: portPointer, EndPort: endPortPointer})
				}
			}
		}
	}
	return ports
}

// ///////////////////////////////////////////////////////////////////////////////
func toPods(model *AbstractModelSyn) []*core.Pod {
	pods := []*core.Pod{}
	for _, vm := range model.vms {
		pod := &core.Pod{}
		pod.TypeMeta.Kind = "Pod"
		pod.TypeMeta.APIVersion = "networking.k8s.io/v1"
		pod.ObjectMeta.Name = vm.Name()
		pod.ObjectMeta.UID = types.UID(vm.ID())
		if len(model.epToGroups[vm]) == 0 {
			continue
		}
		pod.ObjectMeta.Labels = map[string]string{}
		for _, group := range model.epToGroups[vm] {
			label := fmt.Sprintf("group__%s", group.Name())
			pod.ObjectMeta.Labels[label] = label
		}
		pods = append(pods, pod)
	}
	return pods
}

///////////////////////////////////////////////////////////////////////////

func listConn(outDir, format string) (string, error) {
	analyzer := connlist.NewConnlistAnalyzer(connlist.WithOutputFormat(format))

	conns, _, err := analyzer.ConnlistFromDirPath(outDir)
	if err != nil {
		return "", err
	}
	return analyzer.ConnectionsListToString(conns)
}
