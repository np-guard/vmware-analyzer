package model

import (
	"os"
	"slices"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"

	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

const (
	anyStr = "ANY" // ANY can specify any service or any src/dst in DFW rules
)

func NewNSXConfigParserFromFile(fileName string) (*NSXConfigParser, error) {
	res := &NSXConfigParser{file: fileName}

	inputConfigContent, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	rc, err := collector.FromJSONString(inputConfigContent)
	if err != nil {
		return nil, err
	}
	res.rc = rc
	return res, nil
}

func NewNSXConfigParserFromResourcesContainer(rc *collector.ResourcesContainerModel) *NSXConfigParser {
	return &NSXConfigParser{
		rc: rc,
	}
}

type NSXConfigParser struct {
	file         string
	rc           *collector.ResourcesContainerModel
	configRes    *Config
	allGroupsVMs []*endpoints.VM
}

func (p *NSXConfigParser) RunParser() error {
	logging.Debugf("started parsing the given NSX config")
	p.configRes = &Config{}
	p.getVMs() // get vms config
	p.getDFW() // get distributed firewall config
	return nil
}

func (p *NSXConfigParser) GetConfig() *Config {
	return p.configRes
}

// getVMs assigns the parsed VM objects from the NSX resources container into the res config object
func (p *NSXConfigParser) getVMs() {
	p.configRes.vmsMap = map[string]*endpoints.VM{}
	for i := range p.rc.VirtualMachineList {
		vm := &p.rc.VirtualMachineList[i]
		if vm.DisplayName == nil {
			continue
			// skip vm without name
		}
		vmObj := endpoints.NewVM(*vm.DisplayName)
		p.configRes.vms = append(p.configRes.vms, vmObj)
		p.configRes.vmsMap[*vm.DisplayName] = vmObj
	}
}

func (p *NSXConfigParser) getDFW() {
	p.configRes.fw = dfw.NewEmptyDFW(false) // TODO: what is global default?
	for i := range p.rc.DomainList {
		domainRsc := p.rc.DomainList[i].Resources
		for j := range domainRsc.SecurityPolicyList {
			secPolicy := &domainRsc.SecurityPolicyList[j]
			if secPolicy.Category == nil {
				continue // skip secPolicy with nil category (add warning)
			}
			category := *secPolicy.Category
			// more fields to consider: sequence_number , stateful,tcp_strict, unique_id

			// This scope will take precedence over rule level scope.
			scope := p.getEndpointsFromGroupsPaths(secPolicy.Scope)
			policyHasScope := !slices.Equal(secPolicy.Scope, []string{anyStr})

			rules := secPolicy.Rules
			for i := range rules {
				rule := &rules[i]
				r := p.getDFWRule(rule)
				r.scope = scope // scope from policy
				if !policyHasScope {
					// if policy scope is not configured, rule's scope takes effect
					r.scope = p.getEndpointsFromGroupsPaths(rule.Scope)
				}
				r.secPolicyName = *secPolicy.DisplayName
				p.addFWRule(r, category, rule)
			}

			// add default rule if such is configured
			if secPolicy.DefaultRule != nil {
				if secPolicy.ConnectivityPreference == nil || *secPolicy.ConnectivityPreference ==
					nsx.SecurityPolicyConnectivityPreferenceNONE {
					logging.Debugf("unexpected default rule with no ConnectivityPreference")
				}

				defaultRule := p.getDefaultRule(secPolicy)
				if defaultRule == nil {
					logging.Debugf("skipping default rule for policy %s\n", *secPolicy.DisplayName)
				} else {
					defaultRule.scope = scope
					defaultRule.secPolicyName = *secPolicy.DisplayName
					p.addFWRule(defaultRule, category, nil)
				}
			}
		}
	}
}

func (p *NSXConfigParser) addFWRule(r *parsedRule, category string, origRule *collector.Rule) {
	p.configRes.fw.AddRule(r.srcVMs, r.dstVMs, r.conn, category, r.action, r.direction, r.ruleID, origRule, r.scope, r.secPolicyName)
}

func (p *NSXConfigParser) getDefaultRule(secPolicy *collector.SecurityPolicy) *parsedRule {
	// from spec documentation:
	// The default rule that gets created will be a any-any rule and applied
	// to entities specified in the scope of the security policy.
	res := &parsedRule{}
	// scope - the list of group paths where the rules in this policy will get applied.
	scope := secPolicy.Scope
	vms := p.getEndpointsFromGroupsPaths(scope)
	// rule applied as any-to-any only for ths VMs in the scope of the SecurityPolicy
	res.srcVMs = vms
	res.dstVMs = vms

	switch string(*secPolicy.ConnectivityPreference) {
	case string(nsx.SecurityPolicyConnectivityPreferenceALLOWLIST),
		string(nsx.SecurityPolicyConnectivityPreferenceALLOWLISTENABLELOGGING):
		res.action = string(nsx.RuleActionDROP)
	case string(nsx.SecurityPolicyConnectivityPreferenceDENYLIST),
		string(nsx.SecurityPolicyConnectivityPreferenceDENYLISTENABLELOGGING):
		res.action = string(nsx.RuleActionALLOW)
	default:
		logging.Debugf("unexpected default rule action")
		return nil
	}
	res.conn = netset.AllTransports()
	res.ruleID = *secPolicy.DefaultRuleId
	res.direction = string(nsx.RuleDirectionINOUT)
	return res
}

type parsedRule struct {
	srcVMs        []*endpoints.VM
	dstVMs        []*endpoints.VM
	action        string
	conn          *netset.TransportSet
	direction     string
	ruleID        int
	scope         []*endpoints.VM
	secPolicyName string
}

func (p *NSXConfigParser) allGroups() []*endpoints.VM {
	if len(p.allGroupsVMs) > 0 {
		return p.allGroupsVMs
	}
	res := []*endpoints.VM{}
	for i := range p.rc.DomainList {
		domainRsc := &p.rc.DomainList[i].Resources
		for j := range domainRsc.GroupList {
			res = append(res, p.membersToVMsList(domainRsc.GroupList[j].Members)...)
		}
	}
	p.allGroupsVMs = res
	return res
}

func (p *NSXConfigParser) getEndpointsFromGroupsPaths(groupsPaths []string) []*endpoints.VM {
	if slices.Contains(groupsPaths, anyStr) {
		// TODO: if a VM is not within any group, this should not include that VM?
		return p.allGroups() // all groups
	}
	res := []*endpoints.VM{}
	// TODO: support IP Addresses in groupsPaths
	for _, groupPath := range groupsPaths {
		res = append(res, p.getGroupVMs(groupPath)...)
	}
	return res
}

// type *collector.FirewallRule is deprecated but used to collect default rule per securityPolicy
/*func (p *NSXConfigParser) getDFWRule(rule *collector.FirewallRule) *parsedRule {

}*/

func (p *NSXConfigParser) getDFWRule(rule *collector.Rule) *parsedRule {
	if rule.Action == nil {
		return nil // skip rule without action (Add warning)
	}

	res := &parsedRule{}
	srcGroups := rule.SourceGroups // paths of the source groups
	// If set to true, the rule gets applied on all the groups that are NOT part of
	// the source groups. If false, the rule applies to the source groups
	// TODO: handle excluded fields
	// srcExclude := rule.SourcesExcluded
	res.srcVMs = p.getEndpointsFromGroupsPaths(srcGroups)
	dstGroups := rule.DestinationGroups
	res.dstVMs = p.getEndpointsFromGroupsPaths(dstGroups)

	res.action = string(*rule.Action)
	res.conn = p.getRuleConnections(rule)
	res.direction = string(rule.Direction)
	res.ruleID = *rule.RuleId
	return res
}

func (p *NSXConfigParser) getRuleConnections(rule *collector.Rule) *netset.TransportSet {
	/*
		// In order to specify raw services this can be used, along with services which
		// contains path to services. This can be empty or null.
		ServiceEntries []ServiceEntry `json:"service_entries,omitempty" yaml:"service_entries,omitempty" mapstructure:"service_entries,omitempty"`

		// In order to specify all services, use the constant "ANY". This is case
		// insensitive. If "ANY" is used, it should be the ONLY element in the services
		// array. Error will be thrown if ANY is used in conjunction with other values.
		Services []string `json:"services,omitempty" yaml:"services,omitempty" mapstructure:"services,omitempty"`
	*/
	if slices.Contains(rule.Services, anyStr) {
		return netset.AllTransports()
	}
	res := netset.NoTransports()
	for _, s := range rule.Services {
		conn := p.connectionFromService(s, rule)
		if conn != nil {
			res = res.Union(conn)
		}
	}

	return res
}

// connectionFromService returns the set of connections from a service config within the given rule
func (p *NSXConfigParser) connectionFromService(servicePath string, rule *collector.Rule) *netset.TransportSet {
	res := netset.NoTransports()
	service := p.rc.GetService(servicePath)
	if service == nil {
		logging.Debugf("GetService failed to find service %s\n", servicePath)
		return nil
	}
	for _, serviceEntry := range service.ServiceEntries {
		conn, err := serviceEntry.ToConnection()
		if conn != nil && err == nil {
			res = res.Union(conn)
		} else if err != nil {
			logging.Debugf("err: %s", err.Error())
			logging.Debugf("ignoring this service within rule id %d\n", *rule.RuleId)
		}
	}
	logging.Debugf("service path: %s, conn: %s\n", servicePath, res.String())
	return res
}

func (p *NSXConfigParser) membersToVMsList(members []collector.RealizedVirtualMachine) []*endpoints.VM {
	res := []*endpoints.VM{}
	for i := range members {
		vm := &members[i]
		if vm.DisplayName == nil {
			continue
		}
		vmName := *vm.DisplayName
		if vmObj, ok := p.configRes.vmsMap[vmName]; ok {
			res = append(res, vmObj)
		}
		// else: add warning that could not find that vm name in the config
	}
	return res
}

func (p *NSXConfigParser) getGroupVMs(groupPath string) []*endpoints.VM {
	for i := range p.rc.DomainList {
		domainRsc := p.rc.DomainList[i].Resources
		for j := range domainRsc.GroupList {
			g := &domainRsc.GroupList[j]
			if g.Path != nil && groupPath == *g.Path {
				return p.membersToVMsList(g.Members)
			}
		}
	}
	return nil // could not find given groupPath (add warning)
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// comments for later

// scope := secPolicy.Scope // support ANY at first
// more fields to consider: sequence_number , stateful,tcp_strict, unique_id
/*
	If there are multiple policies with the same
		// sequence number then their order is not deterministic. If a specific order of
		// policies is desired, then one has to specify unique sequence numbers or use the
		// POST request on the policy entity with a query parameter action=revise to let
		// the framework assign a sequence number. The value of sequence number must be
		// between 0 and 999,999.
*/
