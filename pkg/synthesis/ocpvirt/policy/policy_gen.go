package policy

import (
	"fmt"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/model/symbolicexpr"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/resources"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/topology"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

// PolicyGenerator implements the functionality to generate network policy resources from the abstract model
type PolicyGenerator struct {
	// input objects for generation
	NamespacesInfo  *topology.NamespacesInfo
	ExternalIP      *netset.IPBlock
	synthModel      *model.AbstractModelSyn
	createDNSPolicy bool

	// internal caching
	conjunctionToSelector map[string]*policySelector

	// additional output indicators
	NotFullySupported bool

	// generated resources
	resources.Generated
}

func NewPolicyGenerator(synthModel *model.AbstractModelSyn, createDNSPolicy bool) *PolicyGenerator {
	return &PolicyGenerator{
		synthModel:      synthModel,
		ExternalIP:      synthModel.ExternalIP,
		createDNSPolicy: createDNSPolicy,

		conjunctionToSelector: map[string]*policySelector{},
	}
}

// main func to generate policy resources
func (np *PolicyGenerator) Generate(ni *topology.NamespacesInfo) {
	np.NamespacesInfo = ni

	if np.createDNSPolicy {
		if np.synthModel.SynthesizeAdmin {
			np.addDNSAllowAdminNetworkPolicy()
		} else {
			np.addDNSAllowNetworkPolicy()
		}
	}

	for _, symbolicPolicy := range np.synthModel.Policy {
		for _, rule := range symbolicPolicy.SortRules() {
			np.symbolicRuleToPolicies(rule, symbolicPolicy.IsInbound(rule))
		}
	}

	np.addDefaultDenyNetworkPolicy()
}

func (np *PolicyGenerator) symbolicRuleToPolicies(rule *model.SymbolicRule, isInbound bool) {
	// todo: be more flexible in admin policy generation,
	// consider enabling also last category as admin target, e.g. if no jump-to-app action is used.
	isAdmin := np.synthModel.SynthesizeAdmin && rule.OrigRuleCategory < collector.MinNonAdminCategory()

	// paths for generating policy rules - either "allow-only flattening" or original nsx structure(allow/deny with priorities)
	paths := rule.OptimizedAllowOnlyPaths
	if isAdmin {
		paths = *rule.OrigSymbolicPaths
	}

	for _, p := range paths {
		if !p.Conn.TCPUDPSet().IsEmpty() {
			np.symbolicPathToPolicy(p, isInbound, isAdmin, rule.OrigRule.Action, rule.OrigRule.RuleIDStr())
		} else {
			logging.Infof("did not create the following k8s %s policy for nsx rule %d, since connection %s is not supported: %s",
				directionStr(isInbound), rule.OrigRule.RuleID, p.Conn.String(), p.String())
		}
	}
}

func (np *PolicyGenerator) symbolicPathToPolicy(path *symbolicexpr.SymbolicPath, isInbound, isAdmin bool,
	action dfw.RuleAction, nsxRuleID string) {
	srcSelector := np.createSelector(path.Src)
	dstSelector := np.createSelector(path.Dst)
	if len(srcSelector.namespaces) == 0 && !isInbound {
		logging.Debugf("skip symbolicPathToPolicy for path [%s] , due to empty namespaces list on src", path.String())
		return
	}
	if len(dstSelector.namespaces) == 0 && isInbound {
		logging.Debugf("skip symbolicPathToPolicy for path [%s] , due to empty namespaces list on dst", path.String())
		return
	}
	if len(srcSelector.namespaces) == 0 {
		logging.Debugf("empty srcSelector.namespaces")
	}
	if len(dstSelector.namespaces) == 0 {
		logging.Debugf("empty dstSelector.namespaces")
	}

	if isAdmin && isInbound && !srcSelector.isTautology() && len(srcSelector.cidrs) > 0 {
		logging.Warnf("Ignoring symbolic-path [ %s ] : ANP with src IP peers for Ingress is not supported", path.String())
		np.NotFullySupported = true
		return
	}
	description := policyDescriptionFromSymbolicPath(path, isAdmin, action.String())

	if isAdmin {
		adminAction := abstractToAdminRuleAction[action]
		np.addAdminNetworkPolicy(srcSelector, dstSelector, path.Conn, isInbound,
			adminAction, description, nsxRuleID)
	} else {
		np.addNetworkPolicy(srcSelector, dstSelector, path.Conn, isInbound, description, nsxRuleID)
	}
}

func policyDescriptionFromSymbolicPath(path *symbolicexpr.SymbolicPath, isAdmin bool, action string) string {
	if isAdmin {
		return fmt.Sprintf("(%s: (%s)", action, path.String())
	}
	return path.String()
}

func (np *PolicyGenerator) createSelector(con symbolicexpr.Term) *policySelector {
	if con == nil {
		return newEmptyPolicySelector()
	}

	if cachedRes := np.conjunctionToSelector[con.String()]; cachedRes != nil {
		logging.Debug2f("pulling from cache for conjunction %s , the following policySelector: %s", con.String(), cachedRes.string())
		// todo: result can currently be changed, thus returning a copy object
		res := *cachedRes
		return &res
	}
	logging.Debug2f("createSelector for conj: %s", con.String())
	boolToOperator := map[bool]meta.LabelSelectorOperator{
		false: meta.LabelSelectorOpExists,
		true:  meta.LabelSelectorOpDoesNotExist}

	res := &policySelector{
		pods:       &meta.LabelSelector{},
		namespaces: np.NamespacesInfo.GetConjunctionNamespaces(con),
	}

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
	np.conjunctionToSelector[con.String()] = res
	logging.Debug2f("caching for conjunction %s , the following policySelector: %s", con.String(), res.string())
	return res
}
