package synthesis

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

type SynthesisOptions struct {
	Hints           *symbolicexpr.Hints
	SynthesizeAdmin bool
	Color           bool
	CreateDNSPolicy bool
}

func NSXToK8sSynthesis(
	recourses *collector.ResourcesContainerModel,
	options *SynthesisOptions,
) (*k8sResources, error) {
	abstractModel, err := NSXToPolicy(recourses, options)
	if err != nil {
		return nil, err
	}
	return createK8sResources(abstractModel, options.CreateDNSPolicy), nil
}

func NSXToPolicy(recourses *collector.ResourcesContainerModel,
	options *SynthesisOptions) (*AbstractModelSyn, error) {
	parser := model.NewNSXConfigParserFromResourcesContainer(recourses)
	err := parser.RunParser()
	if err != nil {
		return nil, err
	}
	config := parser.GetConfig()
	logging.Debugf("started synthesis")
	preProcessingCategoryToPolicy := preProcessing(config.Fw.CategoriesSpecs)
	preProcessingPolicyStr := printPreProcessingSymbolicPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy, options.Color)
	logging.Debugf("pre processing symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", preProcessingPolicyStr)
	allowOnlyPolicy := computeAllowOnlyRulesForPolicy(config.Fw.CategoriesSpecs, preProcessingCategoryToPolicy,
		options.SynthesizeAdmin, options.Hints)
	forK8sPolicy := policyToPolicyForK8s(&allowOnlyPolicy)
	abstractModel := &AbstractModelSyn{vms: parser.VMs(), epToGroups: parser.GetConfig().GroupsPerVM,
		synthesizeAdmin: options.SynthesizeAdmin, policy: []*symbolicPolicy{&allowOnlyPolicy},
		policyForK8sSynthesis: forK8sPolicy, defaultDenyRule: config.DefaultDenyRule()}
	abstractPolicyStr := strAllowOnlyPolicy(&allowOnlyPolicy, options.Color)
	logging.Debugf("allow only symbolic rules\n~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", abstractPolicyStr)
	k8sSynthesisInputStr := strPolicyForK8s(*forK8sPolicy)
	logging.Debugf("k8sSynthesis Input\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n%v", k8sSynthesisInputStr)
	return abstractModel, nil
}

func policyToPolicyForK8s(policy *symbolicPolicy) *symbolicPolicyK8sSynthesis {
	idToPolicyK8sSynthesis := map[int]*symbolicRuleByOrig{}
	insertInOrOutboundByOrigRules(policy.inbound, true, idToPolicyK8sSynthesis)
	insertInOrOutboundByOrigRules(policy.outbound, false, idToPolicyK8sSynthesis)
	res := make(symbolicPolicyK8sSynthesis, len(idToPolicyK8sSynthesis))
	i := 0
	for _, val := range idToPolicyK8sSynthesis {
		res[i] = val
		i++
	}
	return &res
}

func insertInOrOutboundByOrigRules(symbolicRules []*symbolicRule, inbound bool,
	idToPolicyK8sSynthesis map[int]*symbolicRuleByOrig) {
	for _, symRule := range symbolicRules {
		origRuleID := symRule.origRule.RuleID
		entry := symbolicRuleByOrig{}
		if val, ok := idToPolicyK8sSynthesis[origRuleID]; ok {
			entry = *val
		} else {
			entry = symbolicRuleByOrig{origRule: symRule.origRule, allowOnlyOutboundPaths: &symbolicexpr.SymbolicPaths{},
				allowOnlyInboundPaths: &symbolicexpr.SymbolicPaths{}}
		}
		if inbound {
			entry.allowOnlyInboundPaths = &symRule.allowOnlyRulePaths
		} else {
			entry.allowOnlyOutboundPaths = &symRule.allowOnlyRulePaths
		}
		idToPolicyK8sSynthesis[origRuleID] = &entry
	}
}

func strPolicyForK8s(policy symbolicPolicyK8sSynthesis) string {
	var ruleStrFunc = func(r *symbolicRuleByOrig) string {
		return fmt.Sprintf("original rule: %s\n\tinbound symbolic: %s\n\toutbound symbolic: %s",
			r.origRule.String(), r.allowOnlyInboundPaths.String(), r.allowOnlyOutboundPaths.String())
	}
	return common.JoinCustomStrFuncSlice(policy, ruleStrFunc, common.NewLine)
}
