package synthesis

import (
	"fmt"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func NSXToAbstractModelSynthesis(recourses *collector.ResourcesContainerModel) (*symbolicPolicy, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	categoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	fmt.Println(stringCategoryToSymbolicPolicy(config.Fw.CategoriesSpecs, categoryToPolicy))
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, categoryToPolicy)
	readPolicy(&allowOnlyPolicy)
	abstractModel := &AbstractModelSyn{}
	abstractModel.epToGroups = parser.VMsGroups()
	abstractModel.vms = parser.VMs()
	abstractModel.policy = append(abstractModel.policy, &allowOnlyPolicy)
	return &allowOnlyPolicy, nil
}

func readPolicy(p *symbolicPolicy) {
	policies := []*networking.NetworkPolicy{}
	newPolicy := func() *networking.NetworkPolicy {
		pol := &networking.NetworkPolicy{}
		pol.TypeMeta.Kind = "NetworkPolicy"
		pol.TypeMeta.APIVersion = "networking.k8s.io/v1"
		pol.ObjectMeta.Name = fmt.Sprintf("policy_%d", len(policies))
		policies = append(policies, pol)
		return pol
	}
	for _, ob := range p.outbound {
		for _, p := range ob.allowOnlyRulePaths {
			srcSelector := conjunctionToSelector(&p.Src)
			dstSelector := conjunctionToSelector(&p.Dst)
			ports := toPolicyPorts(p.Conn)
			to := []networking.NetworkPolicyPeer{{PodSelector: dstSelector}}
			rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports}}
			pol := newPolicy()
			pol.Spec.Egress = rules
			pol.Spec.PolicyTypes = []networking.PolicyType{"Egress"}
			pol.Spec.PodSelector = *srcSelector
		}
	}
	for _, ib := range p.inbound {
		for _, p := range ib.allowOnlyRulePaths {
			srcSelector := conjunctionToSelector(&p.Src)
			dstSelector := conjunctionToSelector(&p.Dst)
			ports := toPolicyPorts(p.Conn)
			from := []networking.NetworkPolicyPeer{{PodSelector: srcSelector}}
			rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports}}
			pol := newPolicy()
			pol.Spec.Ingress = rules
			pol.Spec.PolicyTypes = []networking.PolicyType{"Ingress"}
			pol.Spec.PodSelector = *dstSelector
		}
	}
	common.WriteYamlUsingJSON(policies, "policies.yaml")
}

func conjunctionToSelector(con *symbolicexpr.Conjunction) *meta.LabelSelector {
	selector := &meta.LabelSelector{}
	for _, a := range *con {
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

func toPolicyPorts(conn *netset.TransportSet) []networking.NetworkPolicyPort {

	ports := []networking.NetworkPolicyPort{}
	tcpSet := conn.TCPUDPSet()
	partitions := tcpSet.Partitions()
	protocol := core.ProtocolTCP
	for _, partition := range partitions {
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
			ports = append(ports, networking.NetworkPolicyPort{Protocol: &protocol, Port: portPointer, EndPort: endPortPointer})
		}
	}
	return ports
}
