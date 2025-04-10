package synthesis

import (
	"fmt"
	"path"
	"regexp"

	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netset"
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
var inboundToDirection = map[bool]networking.PolicyType{
	false: networking.PolicyTypeEgress,
	true:  networking.PolicyTypeIngress,
}

const dnsPort = 53
const dnsLabelKey = "k8s-app"
const dnsLabelVal = "kube-dns"
const noNSXRuleID = "none"

type k8sPolicies struct {
	networkPolicies      []*networking.NetworkPolicy
	adminNetworkPolicies []*admin.AdminNetworkPolicy
	NotFullySupported    bool
	externalIP           *netset.IPBlock
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
			logging.Debugf("did not create the following k8s %s policy for rule %d, since connection %s is not supported: %s",
				inboundToDirection[inbound], rule.origRule.RuleID, p.Conn.String(), p.String())
		}
	}
}

func (policies *k8sPolicies) addNewPolicy(p *symbolicexpr.SymbolicPath, inbound, isAdmin bool, action dfw.RuleAction, nsxRuleID string) {
	policies.NotFullySupported = policies.NotFullySupported || k8sNotFullySupported(p.Src) || k8sNotFullySupported(p.Dst)
	srcSelector := policies.createSelector(p.Src)
	dstSelector := policies.createSelector(p.Dst)
	if isAdmin && inbound && !srcSelector.isTautology() && len(srcSelector.cidrs) > 0 {
		logging.Warnf("Ignoring policy:\n%s\nadmin network policy peer with IPs for Ingress are not supported", p.String())
		policies.NotFullySupported = true
		return
	}
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
func (policies *k8sPolicies) addNetworkPolicy(srcSelector, dstSelector policySelector,
	ports []networking.NetworkPolicyPort, inbound bool,
	description, nsxRuleID string) {
	pol := newNetworkPolicy(fmt.Sprintf("policy-%d", len(policies.networkPolicies)), description, nsxRuleID)
	policies.networkPolicies = append(policies.networkPolicies, pol)
	if inbound {
		from := srcSelector.toPolicyPeers()
		rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports}}
		pol.Spec.Ingress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeIngress}
		pol.Spec.PodSelector = dstSelector.toPodSelector()
	} else {
		to := dstSelector.toPolicyPeers()
		rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports}}
		pol.Spec.Egress = rules
		pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeEgress}
		pol.Spec.PodSelector = srcSelector.toPodSelector()
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

func (policies *k8sPolicies) addAdminNetworkPolicy(srcSelector, dstSelector policySelector,
	ports []admin.AdminNetworkPolicyPort, inbound bool, action admin.AdminNetworkPolicyRuleAction, description, nsxRuleID string) {
	pol := newAdminNetworkPolicy(fmt.Sprintf("admin-policy-%d", len(policies.adminNetworkPolicies)), description, nsxRuleID)
	policies.setAdminNetworkPolicy(pol, ports, inbound, action, srcSelector, dstSelector)
}

func (policies *k8sPolicies) setAdminNetworkPolicy(
	pol *admin.AdminNetworkPolicy, ports []admin.AdminNetworkPolicyPort,
	inbound bool, action admin.AdminNetworkPolicyRuleAction,
	srcSelector, dstSelector policySelector) {
	policies.adminNetworkPolicies = append(policies.adminNetworkPolicies, pol)
	//nolint:gosec // priority should fit int32:
	pol.Spec.Priority = int32(len(policies.adminNetworkPolicies))
	if inbound {
		from := srcSelector.toAdminPolicyIngressPeers()
		rules := []admin.AdminNetworkPolicyIngressRule{{From: from, Action: action, Ports: common.PointerTo(ports)}}
		pol.Spec.Ingress = rules
		pol.Spec.Subject = dstSelector.toAdminPolicySubject()
	} else {
		to := dstSelector.toAdminPolicyEgressPeers()
		rules := []admin.AdminNetworkPolicyEgressRule{{To: to, Action: action, Ports: common.PointerTo(ports)}}
		pol.Spec.Egress = rules
		pol.Spec.Subject = srcSelector.toAdminPolicySubject()
	}
}

func (policies *k8sPolicies) addDNSAllowAdminNetworkPolicy() {
	dnsSelector := policies.createSelector(nil)
	dnsSelector.pods = &meta.LabelSelector{MatchExpressions: []meta.LabelSelectorRequirement{{
		Key:      dnsLabelKey,
		Operator: meta.LabelSelectorOpIn,
		Values:   []string{dnsLabelVal}},
	}}
	dnsSelector.namespace = meta.LabelSelector{MatchExpressions: []meta.LabelSelectorRequirement{}}
	allSelector := policies.createSelector(nil)
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
	pol.Kind = "NetworkPolicy"
	pol.APIVersion = "networking.k8s.io/v1"
	pol.Name = toLegalK8SString(name)
	pol.Namespace = meta.NamespaceDefault
	pol.Annotations = map[string]string{
		annotationDescription: description,
		annotationUID:         nsxRuleID,
	}
	return pol
}

func newAdminNetworkPolicy(name, description, nsxRuleID string) *admin.AdminNetworkPolicy {
	pol := &admin.AdminNetworkPolicy{}
	pol.Kind = "AdminNetworkPolicy"
	pol.APIVersion = "policy.networking.k8s.io/v1alpha1"
	pol.Name = toLegalK8SString(name)
	pol.Annotations = map[string]string{
		annotationDescription: description,
		annotationUID:         nsxRuleID,
	}
	return pol
}

// //////////////////////////////////////////////////////////////////////////////////////////
// policySelector represent a k8s selector. to be later translated to peer, pod selector, etc..
// ite represent one of the follow:
// 1. OR of cidrs.
// 2. a label selector of pods
type policySelector struct {
	pods      *meta.LabelSelector
	cidrs     []string
	namespace meta.LabelSelector
}

func (selector *policySelector) isTautology() bool {
	return len(selector.cidrs) == 1 && selector.cidrs[0] == netset.CidrAll
}

func (selector *policySelector) convertAllCidrToAllPodsSelector() {
	selector.cidrs = []string{}
}

func (policies *k8sPolicies) createSelector(con symbolicexpr.Conjunction) policySelector {
	boolToOperator := map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}

	res := policySelector{pods: &meta.LabelSelector{},
		namespace: meta.LabelSelector{MatchLabels: map[string]string{namespaceNameKey: meta.NamespaceDefault}}}
	for _, a := range con {
		switch {
		case a.IsTautology():
			res.cidrs = []string{netset.CidrAll}
		case a.IsAllGroups():
			// leaving it empty - will match all labels
			// todo: should be fixed when supporting namespaces
		case a.IsAllExternal():
			res.cidrs = policies.externalIP.ToCidrList()
		case a.GetExternalBlock() != nil:
			res.cidrs = a.GetExternalBlock().ToCidrList()
		default:
			label, notIn := a.AsSelector()
			label = toLegalK8SString(label)
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			res.pods.MatchExpressions = append(res.pods.MatchExpressions, req)
		}
	}
	return res
}

func (selector *policySelector) toPolicyPeers() []networking.NetworkPolicyPeer {
	if selector.isTautology() {
		return []networking.NetworkPolicyPeer{
			{IPBlock: &networking.IPBlock{CIDR: netset.CidrAll}},
			{PodSelector: selector.pods}}
	}
	if len(selector.cidrs) > 0 {
		res := make([]networking.NetworkPolicyPeer, len(selector.cidrs))
		for i, cidr := range selector.cidrs {
			res[i] = networking.NetworkPolicyPeer{IPBlock: &networking.IPBlock{CIDR: cidr}}
		}
		return res
	}
	return []networking.NetworkPolicyPeer{{PodSelector: selector.pods}}
}

func (selector *policySelector) toPodSelector() meta.LabelSelector {
	if selector.isTautology() {
		selector.convertAllCidrToAllPodsSelector()
	}
	return *selector.pods
}

func (selector *policySelector) toAdminPolicyIngressPeers() []admin.AdminNetworkPolicyIngressPeer {
	if selector.isTautology() {
		selector.convertAllCidrToAllPodsSelector()
	}
	return []admin.AdminNetworkPolicyIngressPeer{
		{Pods: &admin.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: selector.namespace}}}
}
func (selector *policySelector) toAdminPolicyEgressPeers() []admin.AdminNetworkPolicyEgressPeer {
	if selector.isTautology() {
		return []admin.AdminNetworkPolicyEgressPeer{
			{Networks: []admin.CIDR{admin.CIDR(netset.CidrAll)}},
			{Pods: &admin.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: selector.namespace}}}
	}

	if len(selector.cidrs) > 0 {
		res := make([]admin.AdminNetworkPolicyEgressPeer, len(selector.cidrs))
		for i, cidr := range selector.cidrs {
			res[i] = admin.AdminNetworkPolicyEgressPeer{Networks: []admin.CIDR{admin.CIDR(cidr)}}
		}
		return res
	}
	return []admin.AdminNetworkPolicyEgressPeer{
		{Pods: &admin.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: selector.namespace}}}
}
func (selector *policySelector) toAdminPolicySubject() admin.AdminNetworkPolicySubject {
	if selector.isTautology() {
		selector.convertAllCidrToAllPodsSelector()
	}
	return admin.AdminNetworkPolicySubject{
		Pods: &admin.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: selector.namespace}}
}

// //////////////////////////////////////////////////////////////////////////////////////////
// toLegalK8SString() replaces all the k8s illegal characters with "-NLC"
// allowed characters are letters, numbers, '-', '.', '_'
// this is a temp fix, still todo:
// 1. two different illegal tags might create the same tag
// 2. fix for pods names should be more restrict (only lower, no '_', ...)
var reg = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

func toLegalK8SString(s string) string {
	return reg.ReplaceAllString(s, "-NLC")
}

// a tmp function, mark all the cases we do not support correctly
func k8sNotFullySupported(con symbolicexpr.Conjunction) bool {
	for _, a := range con {
		switch {
		case !a.IsAllExternal() && a.GetExternalBlock() != nil && len(con) > 1:
			logging.InternalErrorf("symbolicexpr.Conjunction %s can not have both IP and labels", con.String())
			return true
		case a.IsSegment():
			return true
		}
	}
	return false
}
