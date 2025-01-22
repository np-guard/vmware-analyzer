package synthesis

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

type k8sPolicies struct {
	networkPolicies      []*networking.NetworkPolicy
	adminNetworkPolicies []*admin.AdminNetworkPolicy
}

func newK8sPolicies() *k8sPolicies {
	return &k8sPolicies{}
}

func (policies *k8sPolicies) toNetworkPolicies(model *AbstractModelSyn) ([]*networking.NetworkPolicy, []*admin.AdminNetworkPolicy) {
	for _, p := range model.policy {
		policies.symbolicRulesToPolicies(model, p.outbound, false)
		policies.symbolicRulesToPolicies(model, p.inbound, true)
	}
	return policies.networkPolicies, policies.adminNetworkPolicies
}

func (policies *k8sPolicies) symbolicRulesToPolicies(model *AbstractModelSyn, rules []*symbolicRule, inbound bool) {
	for _, ob := range rules {
		admin := model.allowOnlyFromCategory > ob.origRuleCategory
		paths := &ob.allowOnlyRulePaths
		if admin {
			paths = ob.origSymbolicPaths
		}
		for _, p := range *paths {
			policies.addNewPolicy(p, inbound, admin, ob.origRule.Action)
		}
	}
}

var abstractToAdminRuleAction = map[dfw.RuleAction]admin.AdminNetworkPolicyRuleAction{
	dfw.ActionAllow:     admin.AdminNetworkPolicyRuleActionAllow,
	dfw.ActionDeny:      admin.AdminNetworkPolicyRuleActionDeny,
	dfw.ActionJumpToApp: admin.AdminNetworkPolicyRuleActionPass,
}

func isEmpty(p *symbolicexpr.SymbolicPath) bool {
	return p.Conn.TCPUDPSet().IsEmpty()
}
func (policies *k8sPolicies) addNewPolicy(p *symbolicexpr.SymbolicPath, inbound, admin bool, action dfw.RuleAction) {
	if isEmpty(p) {
		return
	}
	srcSelector := toSelector(p.Src)
	dstSelector := toSelector(p.Dst)
	if admin {
		ports := &k8sAdminNetworkPorts{}
		toPolicyPorts(ports, p.Conn, admin)
		policies.addAdminNetworkPolicy(srcSelector, dstSelector, ports.ports, inbound,
			abstractToAdminRuleAction[action], fmt.Sprintf("(%s: (%s)", action, p.String()))
	} else {
		ports := &k8sNetworkPorts{}
		toPolicyPorts(ports, p.Conn, admin)
		policies.addNetworkPolicy(srcSelector, dstSelector, ports.ports, inbound, p.String())
	}
}

func toSelector(con symbolicexpr.Conjunction) *meta.LabelSelector {
	boolToOperator := map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}
	selector := &meta.LabelSelector{}
	for _, a := range con {
		if !a.IsTautology() { // not tautology
			label, notIn := a.AsSelector()
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}

func (policies *k8sPolicies) addNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports []networking.NetworkPolicyPort, inbound bool,
	description string) {
	pol := newNetworkPolicy(fmt.Sprintf("policy_%d", len(policies.networkPolicies)), description)
	policies.networkPolicies = append(policies.networkPolicies, pol)
	if inbound {
		from := []networking.NetworkPolicyPeer{{PodSelector: srcSelector}}
		rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports}}
		pol.Spec.Ingress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{"Ingress"}
		pol.Spec.PodSelector = *dstSelector
	} else {
		to := []networking.NetworkPolicyPeer{{PodSelector: dstSelector}}
		rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports}}
		pol.Spec.Egress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{"Egress"}
		pol.Spec.PodSelector = *srcSelector
	}
}

func (policies *k8sPolicies) addAdminNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports []admin.AdminNetworkPolicyPort, inbound bool, action admin.AdminNetworkPolicyRuleAction, description string) {
	pol := newAdminNetworkPolicy(fmt.Sprintf("policy_%d", len(policies.adminNetworkPolicies)), description)
	policies.adminNetworkPolicies = append(policies.adminNetworkPolicies, pol)
	pol.Spec.Priority = int32(len(policies.adminNetworkPolicies))
	srcPodsSelector := &admin.NamespacedPod{PodSelector: *srcSelector}
	dstPodsSelector := &admin.NamespacedPod{PodSelector: *dstSelector}
	if inbound {
		from := []admin.AdminNetworkPolicyIngressPeer{{Pods: srcPodsSelector}}
		rules := []admin.AdminNetworkPolicyIngressRule{{From: from, Action: action, Ports: pointerTo(ports)}}
		pol.Spec.Ingress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Pods: dstPodsSelector}
	} else {
		to := []admin.AdminNetworkPolicyEgressPeer{{Pods: dstPodsSelector}}
		rules := []admin.AdminNetworkPolicyEgressRule{{To: to, Action: action, Ports: pointerTo(ports)}}
		pol.Spec.Egress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Pods: srcPodsSelector}
	}
}

func newNetworkPolicy(name, description string) *networking.NetworkPolicy {
	pol := &networking.NetworkPolicy{}
	pol.TypeMeta.Kind = "NetworkPolicy"
	pol.TypeMeta.APIVersion = "networking.k8s.io/v1"
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{"description": description}
	return pol
}

func newAdminNetworkPolicy(name, description string) *admin.AdminNetworkPolicy {
	pol := &admin.AdminNetworkPolicy{}
	pol.TypeMeta.Kind = "AdminNetworkPolicy"
	pol.TypeMeta.APIVersion = "policy.networking.k8s.io/v1alpha1"
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{"description": description}
	return pol
}
