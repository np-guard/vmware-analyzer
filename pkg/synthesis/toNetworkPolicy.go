package synthesis

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func ToNetworkPolicies(p *symbolicPolicy) []*networking.NetworkPolicy {
	policies := []*networking.NetworkPolicy{}
	addNewPolicy := func(description string) *networking.NetworkPolicy {
		pol := newNetworkPolicy(fmt.Sprintf("policy_%d", len(policies)), description)
		policies = append(policies, pol)
		return pol
	}
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

func conjunctionToSelector(con symbolicexpr.Conjunction) *meta.LabelSelector {
	selector := &meta.LabelSelector{}
	for _, a := range con {
		key, notIn, vals := a.AsSelector()
		switch {
		case len(vals) == 0: // tautology
		case !notIn && len(vals) == 1:
			selector.MatchLabels = map[string]string{key: vals[0]}
		case !notIn:
			req := meta.LabelSelectorRequirement{Key: key, Operator: meta.LabelSelectorOpIn, Values: vals}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		case notIn:
			req := meta.LabelSelectorRequirement{Key: key, Operator: meta.LabelSelectorOpNotIn, Values: vals}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}

func pointerTo[T any](t T) *T {
	return &t
}

func toPolicyPorts(conn *netset.TransportSet) []networking.NetworkPolicyPort {

	ports := []networking.NetworkPolicyPort{}
	if conn.IsAll() {
		return []networking.NetworkPolicyPort{}
	}
	tcpUdpSet := conn.TCPUDPSet()
	icmpSet := conn.ICMPSet()
	if tcpUdpSet.IsAll() {
		ports = append(ports, networking.NetworkPolicyPort{Protocol: pointerTo(core.ProtocolTCP), Port: nil, EndPort: nil})
		ports = append(ports, networking.NetworkPolicyPort{Protocol: pointerTo(core.ProtocolUDP), Port: nil, EndPort: nil})
	} else {
		partitions := tcpUdpSet.Partitions()
		for _, partition := range partitions {
			protocols := partition.S1.Intervals()[0]
			portRanges := partition.S3
			for _, portRange := range portRanges.Intervals() {
				var portPointer *intstr.IntOrString
				var endPortPointer *int32

				port := intstr.FromInt(int(portRange.Start()))
				portPointer = &port
				if portRange.End() != portRange.Start() {
					endPort := int32(portRange.End())
					endPortPointer = &endPort
				}
				for _, protocolCode := range protocols.Elements() {
					protocol := core.ProtocolTCP
					if protocolCode == netset.UDPCode {
						protocol = core.ProtocolUDP
					}
					ports = append(ports, networking.NetworkPolicyPort{Protocol: &protocol, Port: portPointer, EndPort: endPortPointer})
				}
			}
		}
	}
	if !icmpSet.IsEmpty() {
		ports = append(ports, networking.NetworkPolicyPort{Protocol: pointerTo(core.ProtocolSCTP), Port: nil, EndPort: nil})

	}
	return ports
}
