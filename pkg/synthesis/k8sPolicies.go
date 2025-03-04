package synthesis

import (
	"fmt"
	"path"
	"regexp"

	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/symbolicexpr"
)

var abstractToAdminRuleAction = map[dfw.RuleAction]admin.AdminNetworkPolicyRuleAction{
	dfw.ActionAllow:     admin.AdminNetworkPolicyRuleActionAllow,
	dfw.ActionDeny:      admin.AdminNetworkPolicyRuleActionDeny,
	dfw.ActionJumpToApp: admin.AdminNetworkPolicyRuleActionPass,
}

const dnsPort = 53
const dnsLabelKey = "k8s-app"
const dnsLabelVal = "kube-dns"
const noNSXRuleID = "none"

type k8sPolicies struct {
	networkPolicies      []*networking.NetworkPolicy
	adminNetworkPolicies []*admin.AdminNetworkPolicy
}

func (policies *k8sPolicies) createPolicies(model *AbstractModelSyn, createDNSPolicy bool) {
	if createDNSPolicy {
		if model.synthesizeAdmin {
			policies.addDNSAllowAdminNetworkPolicy()
		} else {
			policies.addDNSAllowNetworkPolicy()
		}
	}
	for _, p := range model.policy {
		for _, rule := range p.sortRules() {
			policies.symbolicRulesToPolicies(model, rule, p.isInbound(rule))
		}
	}
	policies.addDefaultDenyNetworkPolicy(model.defaultDenyRule)
}

func (policies *k8sPolicies) symbolicRulesToPolicies(model *AbstractModelSyn, rule *symbolicRule, inbound bool) {
	isAdmin := model.synthesizeAdmin && rule.origRuleCategory < collector.MinNonAdminCategory()
	paths := &rule.optimizedAllowOnlyPaths
	if isAdmin {
		paths = rule.origSymbolicPaths
	}
	for _, p := range *paths {
		if !p.Conn.TCPUDPSet().IsEmpty() {
			policies.addNewPolicy(p, inbound, isAdmin, rule.origRule.Action, rule.origRule.RuleIDStr())
		} else {
			logging.Debugf("do not create a k8s policy for rule %s - connection %s is not supported", rule.origRule.String(), p.Conn.String())
		}
	}
}

func (policies *k8sPolicies) addNewPolicy(p *symbolicexpr.SymbolicPath, inbound, isAdmin bool, action dfw.RuleAction, nsxRuleID string) {
	srcSelector := toSelector(p.Src)
	dstSelector := toSelector(p.Dst)
	if isAdmin {
		ports := connToAdminPolicyPort(p.Conn)
		policies.addAdminNetworkPolicy(srcSelector, dstSelector, ports, inbound,
			abstractToAdminRuleAction[action], fmt.Sprintf("(%s: (%s)", action, p.String()), nsxRuleID)
	} else {
		ports := connToPolicyPort(p.Conn)
		policies.addNetworkPolicy(srcSelector, dstSelector, ports, inbound, p.String(), nsxRuleID)
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////
func (policies *k8sPolicies) addNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports []networking.NetworkPolicyPort, inbound bool,
	description, nsxRuleID string) {
	pol := newNetworkPolicy(fmt.Sprintf("policy-%d", len(policies.networkPolicies)), description, nsxRuleID)
	policies.networkPolicies = append(policies.networkPolicies, pol)
	if inbound {
		from := []networking.NetworkPolicyPeer{{PodSelector: srcSelector}}
		rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports}}
		pol.Spec.Ingress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeIngress}
		pol.Spec.PodSelector = *dstSelector
	} else {
		to := []networking.NetworkPolicyPeer{{PodSelector: dstSelector}}
		rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports}}
		pol.Spec.Egress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeEgress}
		pol.Spec.PodSelector = *srcSelector
	}
}

func (policies *k8sPolicies) addDefaultDenyNetworkPolicy(defaultRule *dfw.FwRule) {
	ruleID := noNSXRuleID
	if defaultRule != nil {
		ruleID = defaultRule.RuleIDStr()
	}
	pol := newNetworkPolicy("default-deny", "Default Deny Network Policy", ruleID)
	policies.networkPolicies = append(policies.networkPolicies, pol)
	pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeIngress, networking.PolicyTypeEgress}
}

func (policies *k8sPolicies) addDNSAllowNetworkPolicy() {
	pol := newNetworkPolicy("dns-policy", "Network Policy To Allow Access To DNS Server", noNSXRuleID)
	policies.networkPolicies = append(policies.networkPolicies, pol)
	pol.Spec.PodSelector = meta.LabelSelector{}
	to := []networking.NetworkPolicyPeer{{
		PodSelector:       &meta.LabelSelector{MatchLabels: map[string]string{dnsLabelKey: dnsLabelVal}},
		NamespaceSelector: &meta.LabelSelector{},
	}}
	pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeEgress}
	pol.Spec.Egress = []networking.NetworkPolicyEgressRule{{To: to, Ports: connToPolicyPort(dnsPortConn)}}
}

// //////////////////////////////////////////////////////////////////////////////////////////
var namespaceNameKey = path.Join("kubernetes.io", meta.ObjectNameField)
var defaultNamespaceSelector = meta.LabelSelector{MatchLabels: map[string]string{namespaceNameKey: meta.NamespaceDefault}}

func (policies *k8sPolicies) addAdminNetworkPolicy(srcSelector, dstSelector *meta.LabelSelector,
	ports []admin.AdminNetworkPolicyPort, inbound bool, action admin.AdminNetworkPolicyRuleAction, description, nsxRuleID string) {
	pol := newAdminNetworkPolicy(fmt.Sprintf("admin-policy-%d", len(policies.adminNetworkPolicies)), description, nsxRuleID)
	srcPodsSelector := &admin.NamespacedPod{PodSelector: *srcSelector, NamespaceSelector: defaultNamespaceSelector}
	dstPodsSelector := &admin.NamespacedPod{PodSelector: *dstSelector, NamespaceSelector: defaultNamespaceSelector}
	policies.setAdminNetworkPolicy(pol, ports, inbound, action, srcPodsSelector, dstPodsSelector)
}

func (policies *k8sPolicies) setAdminNetworkPolicy(
	pol *admin.AdminNetworkPolicy, ports []admin.AdminNetworkPolicyPort,
	inbound bool, action admin.AdminNetworkPolicyRuleAction,
	srcPodsSelector, dstPodsSelector *admin.NamespacedPod) {
	policies.adminNetworkPolicies = append(policies.adminNetworkPolicies, pol)
	//nolint:gosec // priority should fit int32:
	pol.Spec.Priority = int32(len(policies.adminNetworkPolicies))
	if inbound {
		from := []admin.AdminNetworkPolicyIngressPeer{{Pods: srcPodsSelector}}
		rules := []admin.AdminNetworkPolicyIngressRule{{From: from, Action: action, Ports: common.PointerTo(ports)}}
		pol.Spec.Ingress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Pods: dstPodsSelector}
	} else {
		to := []admin.AdminNetworkPolicyEgressPeer{{Pods: dstPodsSelector}}
		rules := []admin.AdminNetworkPolicyEgressRule{{To: to, Action: action, Ports: common.PointerTo(ports)}}
		pol.Spec.Egress = rules
		pol.Spec.Subject = admin.AdminNetworkPolicySubject{Pods: srcPodsSelector}
	}
}

func (policies *k8sPolicies) addDNSAllowAdminNetworkPolicy() {
	dnsSelector := &admin.NamespacedPod{
		PodSelector: meta.LabelSelector{MatchExpressions: []meta.LabelSelectorRequirement{{
			Key:      dnsLabelKey,
			Operator: meta.LabelSelectorOpIn,
			Values:   []string{dnsLabelVal}},
		}},
		NamespaceSelector: meta.LabelSelector{MatchExpressions: []meta.LabelSelectorRequirement{}},
	}
	allSelector := &admin.NamespacedPod{NamespaceSelector: defaultNamespaceSelector}
	ports := connToAdminPolicyPort(dnsPortConn)
	egressPol := newAdminNetworkPolicy("egress-dns-policy",
		"Admin Network Policy To Allow Egress Access To DNS Server",
		noNSXRuleID)
	policies.setAdminNetworkPolicy(egressPol, ports, false, admin.AdminNetworkPolicyRuleActionAllow, allSelector, dnsSelector)
}

// //////////////////////////////////////////////////////////////////////////////////////////
const annotationDescription = "description"
const annotationUID = "nsx-id"

func newNetworkPolicy(name, description, nsxRuleID string) *networking.NetworkPolicy {
	pol := &networking.NetworkPolicy{}
	pol.TypeMeta.Kind = "NetworkPolicy"
	pol.TypeMeta.APIVersion = "networking.k8s.io/v1"
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Namespace = meta.NamespaceDefault
	pol.ObjectMeta.Annotations = map[string]string{
		annotationDescription: description,
		annotationUID:         nsxRuleID,
	}
	return pol
}

func newAdminNetworkPolicy(name, description, nsxRuleID string) *admin.AdminNetworkPolicy {
	pol := &admin.AdminNetworkPolicy{}
	pol.TypeMeta.Kind = "AdminNetworkPolicy"
	pol.TypeMeta.APIVersion = "policy.networking.k8s.io/v1alpha1"
	pol.ObjectMeta.Name = name
	pol.ObjectMeta.Annotations = map[string]string{
		annotationDescription: description,
		annotationUID:         nsxRuleID,
	}
	return pol
}

////////////////////////////////////////////////////////////////////////////////////////////

func toSelector(con symbolicexpr.Conjunction) *meta.LabelSelector {
	boolToOperator := map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}
	selector := &meta.LabelSelector{}
	for _, a := range con {
		if !a.IsTautology() {
			label, notIn := a.AsSelector()
			label = toLegalK8SString(label)
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			selector.MatchExpressions = append(selector.MatchExpressions, req)
		}
	}
	return selector
}

func toLegalK8SString(s string) string {
	reg, _ := regexp.Compile(`[^-A-Za-z0-9_.]`)
	return reg.ReplaceAllString(s, "-NLC")
}
