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
	configRes    *config
	allGroupsVMs []*endpoints.VM
}

func (p *NSXConfigParser) RunParser() error {
	logging.Debugf("started parsing the given NSX config")
	p.configRes = &config{}
	p.getVMs() // get vms config
	p.getDFW() // get distributed firewall config
	return nil
}

func (p *NSXConfigParser) GetConfig() *config {
	return p.configRes
}

// getVMs assigns the parsed VM objects from the NSX resources container into the res config object
func (p *NSXConfigParser) getVMs() {
	p.configRes.vmsMap = map[string]*endpoints.VM{}
	for i := range p.rc.VirtualMachineList {
		vm := &p.rc.VirtualMachineList[i]
		if vm.DisplayName == nil || vm.ExternalId == nil {
			// skip vm without name
			logging.Debugf("warning: skipped vm without name/uid at index %d", i)
			continue
		}
		vmObj := endpoints.NewVM(*vm.DisplayName, *vm.ExternalId)
		for _, tag := range vm.Tags {
			vmObj.AddTag(tag.Tag)
			// currently ignoring tag scope
			if tag.Scope != "" {
				logging.Debugf("warning: ignoring tag scope for VM %s, tag: %s, scope: %s", *vm.DisplayName, tag.Tag, tag.Scope)
			}
		}
		p.configRes.vms = append(p.configRes.vms, vmObj)
		p.configRes.vmsMap[vmObj.ID()] = vmObj
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
	// in case rule services is empty(or has "ANY"), and rule serviceEntries is empty, all connections are allowed
	// otherwise, we union the connections of all non "ANY" services and the service entries
	if (len(rule.Services) == 0 || slices.Contains(rule.Services, anyStr)) && len(rule.ServiceEntries) == 0 {
		return netset.AllTransports()
	}
	res := netset.NoTransports()
	for _, s := range rule.Services {
		// currenrly ignoring services "ANY", if ServiceEntries is not empty..
		if s == anyStr {
			logging.Debugf("warning: for rule %d, found rule.Services containing ANY, with non empty serviceEntries. ignoring ANY for this rule.",
				*rule.RuleId)
			continue
		}
		conn := p.connectionFromService(s, rule)
		if conn != nil && !conn.IsEmpty() {
			logging.Debugf("adding rule connection from Service: %s", conn.String())
			res = res.Union(conn)
		}
	}
	conn := p.connectionFromServiceEntries(rule.ServiceEntries, rule)
	if conn != nil && !conn.IsEmpty() {
		logging.Debugf("adding rule connection from ServiceEntries: %s", conn.String())
		res = res.Union(conn)
	}
	return res
}

// connectionFromService returns the set of connections from a service config within the given rule
func (p *NSXConfigParser) connectionFromService(servicePath string, rule *collector.Rule) *netset.TransportSet {
	service := p.rc.GetService(servicePath)
	if service == nil {
		logging.Debugf("GetService failed to find service %s\n", servicePath)
		return nil
	}
	res := p.connectionFromServiceEntries(service.ServiceEntries, rule)
	logging.Debugf("service path: %s, conn: %s\n", servicePath, res.String())
	return res
}

// connectionFromServiceEntries returns the set of connections from a ServiceEntries config within the given rule
func (p *NSXConfigParser) connectionFromServiceEntries(serviceEntries collector.ServiceEntries, rule *collector.Rule) *netset.TransportSet {
	res := netset.NoTransports()
	for _, serviceEntry := range serviceEntries {
		conn, err := serviceEntry.ToConnection()
		switch {
		case conn != nil && err == nil:
			res = res.Union(conn)
		case err != nil:
			logging.Debugf("err: %s", err.Error())
			logging.Debugf("ignoring this service entry within rule id %d\n", *rule.RuleId)
		case conn == nil:
			logging.Debugf("warning: got nil connnection object for serviceEntry object")
		}
	}
	return res
}

func (p *NSXConfigParser) membersToVMsList(members []collector.RealizedVirtualMachine) []*endpoints.VM {
	res := []*endpoints.VM{}
	for i := range members {
		vm := &members[i]
		if vm.Id == nil { // use id instead of DisplayName, assuming matched to vm's external id
			logging.Debugf("skipping member without id, at index %d", i)
			continue
		}
		vmID := *vm.Id
		if vmObj, ok := p.configRes.vmsMap[vmID]; ok {
			res = append(res, vmObj)
		}
		// else: add warning that could not find that vm name in the config
		logging.Debugf("could not find VM id %s in the parsed config", vmID)
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
