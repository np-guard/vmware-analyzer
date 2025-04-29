package policy

import (
	"fmt"
	"path"

	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

type PolicyGenerator struct {
	NamespacesInfo    *topology.NamespacesInfo
	NotFullySupported bool
	ExternalIP        *netset.IPBlock
	synthModel        *model.AbstractModelSyn
	createDNSPolicy   bool

	// generated resources
	NetworkPolicies      []*networking.NetworkPolicy
	AdminNetworkPolicies []*admin.AdminNetworkPolicy
}

func NewPolicyGenerator(synthModel *model.AbstractModelSyn, createDNSPolicy bool) *PolicyGenerator {
	return &PolicyGenerator{
		synthModel:      synthModel,
		ExternalIP:      synthModel.ExternalIP,
		createDNSPolicy: createDNSPolicy,
	}
}

func (np *PolicyGenerator) Generate(ni *topology.NamespacesInfo) {
	np.NamespacesInfo = ni

	if np.createDNSPolicy {
		if np.synthModel.SynthesizeAdmin {
			np.addDNSAllowAdminNetworkPolicy()
		} else {
			np.addDNSAllowNetworkPolicy()
		}
	}
	for _, p := range np.synthModel.Policy {
		for _, rule := range p.SortRules() {
			np.symbolicRulesToPolicies(np.synthModel, rule, p.IsInbound(rule))
		}
	}
	np.addDefaultDenyNetworkPolicy(np.synthModel.DefaultDenyRule)
}

func (np *PolicyGenerator) addDefaultDenyNetworkPolicy(defaultRule *dfw.FwRule) {
	ruleID := noNSXRuleID
	if defaultRule != nil {
		ruleID = defaultRule.RuleIDStr()
	}
	for _, namespace := range np.NamespacesInfo.Namespaces {
		pol := newNetworkPolicy("default-deny", namespace.Name, "Default Deny Network Policy", ruleID)
		np.NetworkPolicies = append(np.NetworkPolicies, pol)
		pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeIngress, networking.PolicyTypeEgress}
	}
}

func (np *PolicyGenerator) symbolicRulesToPolicies(synthModel *model.AbstractModelSyn, rule *model.SymbolicRule, inbound bool) {
	isAdmin := synthModel.SynthesizeAdmin && rule.OrigRuleCategory < collector.MinNonAdminCategory()
	paths := &rule.OptimizedAllowOnlyPaths
	if isAdmin {
		paths = rule.OrigSymbolicPaths
	}
	for _, p := range *paths {
		if !p.Conn.TCPUDPSet().IsEmpty() {
			np.addNewPolicy(p, inbound, isAdmin, rule.OrigRule.Action, rule.OrigRule.RuleIDStr())
		} else {
			logging.Debugf("did not create the following k8s %s policy for rule %d, since connection %s is not supported: %s",
				inboundToDirection[inbound], rule.OrigRule.RuleID, p.Conn.String(), p.String())
		}
	}
}

func (np *PolicyGenerator) addNewPolicy(p *symbolicexpr.SymbolicPath, inbound, isAdmin bool, action dfw.RuleAction, nsxRuleID string) {
	srcSelector := np.createSelector(p.Src)
	dstSelector := np.createSelector(p.Dst)
	if isAdmin && inbound && !srcSelector.isTautology() && len(srcSelector.cidrs) > 0 {
		logging.Warnf("Ignoring policy:\n%s\nadmin network policy peer with IPs for Ingress are not supported", p.String())
		np.NotFullySupported = true
		return
	}
	if isAdmin {
		ports := connToAdminPolicyPort(p.Conn)
		np.addAdminNetworkPolicy(srcSelector, dstSelector, ports, inbound,
			abstractToAdminRuleAction[action], fmt.Sprintf("(%s: (%s)", action, p.String()), nsxRuleID)
	} else {
		ports := connToPolicyPort(p.Conn)
		np.addNetworkPolicy(srcSelector, dstSelector, ports, inbound, p.String(), nsxRuleID)
	}
}

func (np *PolicyGenerator) addNetworkPolicy(srcSelector, dstSelector policySelector,
	ports []networking.NetworkPolicyPort, inbound bool,
	description, nsxRuleID string) {
	newPolicy := func(namespace string) *networking.NetworkPolicy {
		pol := newNetworkPolicy(fmt.Sprintf("policy-%d", len(np.NetworkPolicies)), namespace, description, nsxRuleID)
		np.NetworkPolicies = append(np.NetworkPolicies, pol)
		return pol
	}
	oneSameNamespace := len(srcSelector.namespaces) == 1 &&
		len(dstSelector.namespaces) == 1 &&
		srcSelector.namespaces[0] == dstSelector.namespaces[0]
	if inbound {
		if oneSameNamespace {
			srcSelector.namespaces = nil
		}
		from := srcSelector.toPolicyPeers()
		rules := []networking.NetworkPolicyIngressRule{{From: from, Ports: ports}}
		for _, namespace := range dstSelector.namespaces {
			pol := newPolicy(namespace)
			pol.Spec.Ingress = rules
			pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeIngress}
			pol.Spec.PodSelector = dstSelector.toPodSelector()
		}
	} else {
		if oneSameNamespace {
			dstSelector.namespaces = nil
		}
		to := dstSelector.toPolicyPeers()
		rules := []networking.NetworkPolicyEgressRule{{To: to, Ports: ports}}
		for _, namespace := range srcSelector.namespaces {
			pol := newPolicy(namespace)
			pol.Spec.Egress = rules
			pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeEgress}
			pol.Spec.PodSelector = srcSelector.toPodSelector()
		}
	}
}

func (np *PolicyGenerator) addAdminNetworkPolicy(srcSelector, dstSelector policySelector,
	ports []admin.AdminNetworkPolicyPort, inbound bool, action admin.AdminNetworkPolicyRuleAction, description, nsxRuleID string) {
	pol := newAdminNetworkPolicy(fmt.Sprintf("admin-policy-%d", len(np.AdminNetworkPolicies)), description, nsxRuleID)
	np.setAdminNetworkPolicy(pol, ports, inbound, action, srcSelector, dstSelector)
}

func (np *PolicyGenerator) addDNSAllowNetworkPolicy() {
	for _, namespace := range np.NamespacesInfo.Namespaces {
		pol := newNetworkPolicy("dns-policy", namespace.Name, "Network Policy To Allow Access To DNS Server", noNSXRuleID)
		np.NetworkPolicies = append(np.NetworkPolicies, pol)
		pol.Spec.PodSelector = meta.LabelSelector{}
		to := []networking.NetworkPolicyPeer{{
			PodSelector:       &meta.LabelSelector{MatchLabels: map[string]string{dnsLabelKey: dnsLabelVal}},
			NamespaceSelector: &meta.LabelSelector{},
		}}
		pol.Spec.PolicyTypes = []networking.PolicyType{networking.PolicyTypeEgress}
		pol.Spec.Egress = []networking.NetworkPolicyEgressRule{{To: to, Ports: connToPolicyPort(dnsPortConn)}}
	}
}

func (np *PolicyGenerator) addDNSAllowAdminNetworkPolicy() {
	dnsSelector := np.createSelector(nil)
	dnsSelector.pods = &meta.LabelSelector{MatchExpressions: []meta.LabelSelectorRequirement{{
		Key:      dnsLabelKey,
		Operator: meta.LabelSelectorOpIn,
		Values:   []string{dnsLabelVal}},
	}}
	allSelector := np.createSelector(nil)
	ports := connToAdminPolicyPort(dnsPortConn)
	egressPol := newAdminNetworkPolicy("egress-dns-policy",
		"Admin Network Policy To Allow Egress Access To DNS Server",
		noNSXRuleID)
	np.setAdminNetworkPolicy(egressPol, ports, false, admin.AdminNetworkPolicyRuleActionAllow, allSelector, dnsSelector)
}

func (np *PolicyGenerator) setAdminNetworkPolicy(
	pol *admin.AdminNetworkPolicy, ports []admin.AdminNetworkPolicyPort,
	inbound bool, action admin.AdminNetworkPolicyRuleAction,
	srcSelector, dstSelector policySelector) {
	np.AdminNetworkPolicies = append(np.AdminNetworkPolicies, pol)
	//nolint:gosec // priority should fit int32:
	pol.Spec.Priority = int32(len(np.AdminNetworkPolicies))
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

func (np *PolicyGenerator) createSelector(con symbolicexpr.Conjunction) policySelector {
	boolToOperator := map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}

	res := policySelector{pods: &meta.LabelSelector{}}
	res.namespaces = common.CustomStrSliceToStrings(np.NamespacesInfo.GetConjunctionNamespaces(con),
		func(namespace *topology.Namespace) string { return namespace.Name })
	for _, a := range con {
		switch {
		case a.IsTautology():
			res.cidrs = []string{netset.CidrAll}
		case a.IsAllGroups():
			// leaving it empty - will match all labels
			// todo: should be fixed when supporting namespaces
		case a.IsAllExternal():
			res.cidrs = np.ExternalIP.ToCidrList()
		case a.GetExternalBlock() != nil:
			res.cidrs = a.GetExternalBlock().ToCidrList()
		default:
			label, notIn := a.AsSelector()
			label = utils.ToLegalK8SString(label)
			req := meta.LabelSelectorRequirement{Key: label, Operator: boolToOperator[notIn]}
			res.pods.MatchExpressions = append(res.pods.MatchExpressions, req)
		}
	}
	return res
}

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

var namespaceNameKey = path.Join("kubernetes.io", meta.ObjectNameField)

const annotationDescription = "description"
const annotationUID = "nsx-id"

func newNetworkPolicy(name, namespace, description, nsxRuleID string) *networking.NetworkPolicy {
	pol := &networking.NetworkPolicy{}
	pol.Kind = "NetworkPolicy"
	pol.APIVersion = "networking.k8s.io/v1"
	pol.Name = utils.ToLegalK8SString(name)
	pol.Namespace = namespace
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
	pol.Name = utils.ToLegalK8SString(name)
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
	pods       *meta.LabelSelector
	cidrs      []string
	namespaces []string
}

func (selector *policySelector) namespaceLabelSelector(isAdmin bool) *meta.LabelSelector {
	switch {
	case len(selector.namespaces) > 0:
		return &meta.LabelSelector{MatchExpressions: []meta.LabelSelectorRequirement{
			{Key: namespaceNameKey, Operator: meta.LabelSelectorOpIn, Values: selector.namespaces}}}
	case isAdmin:
		return &meta.LabelSelector{}
	default:
		return nil
	}
}

func (selector *policySelector) isTautology() bool {
	return len(selector.cidrs) == 1 && selector.cidrs[0] == netset.CidrAll
}

func (selector *policySelector) convertAllCidrToAllPodsSelector() {
	selector.cidrs = []string{}
}

func (selector *policySelector) toPolicyPeers() []networking.NetworkPolicyPeer {
	if !selector.isTautology() && len(selector.cidrs) > 0 {
		res := make([]networking.NetworkPolicyPeer, len(selector.cidrs))
		for i, cidr := range selector.cidrs {
			res[i] = networking.NetworkPolicyPeer{IPBlock: &networking.IPBlock{CIDR: cidr}}
		}
		return res
	}
	res := []networking.NetworkPolicyPeer{{PodSelector: selector.pods, NamespaceSelector: selector.namespaceLabelSelector(false)}}
	if selector.isTautology() {
		res = append(res, networking.NetworkPolicyPeer{IPBlock: &networking.IPBlock{CIDR: netset.CidrAll}})
	}
	return res
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
		{Pods: &admin.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: *selector.namespaceLabelSelector(true)}}}
}
func (selector *policySelector) toAdminPolicyEgressPeers() []admin.AdminNetworkPolicyEgressPeer {
	if selector.isTautology() {
		return []admin.AdminNetworkPolicyEgressPeer{
			{Networks: []admin.CIDR{admin.CIDR(netset.CidrAll)}},
			{Pods: &admin.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: *selector.namespaceLabelSelector(true)}}}
	}

	if len(selector.cidrs) > 0 {
		res := make([]admin.AdminNetworkPolicyEgressPeer, len(selector.cidrs))
		for i, cidr := range selector.cidrs {
			res[i] = admin.AdminNetworkPolicyEgressPeer{Networks: []admin.CIDR{admin.CIDR(cidr)}}
		}
		return res
	}
	return []admin.AdminNetworkPolicyEgressPeer{
		{Pods: &admin.NamespacedPod{PodSelector: *selector.pods, NamespaceSelector: *selector.namespaceLabelSelector(true)}}}
}
func (selector *policySelector) toAdminPolicySubject() admin.AdminNetworkPolicySubject {
	if selector.isTautology() {
		selector.convertAllCidrToAllPodsSelector()
	}
	return admin.AdminNetworkPolicySubject{Pods: &admin.NamespacedPod{PodSelector: *selector.pods,
		NamespaceSelector: meta.LabelSelector{MatchLabels: map[string]string{namespaceNameKey: meta.NamespaceDefault}}}}
}
