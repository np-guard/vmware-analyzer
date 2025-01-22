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
	file                   string
	rc                     *collector.ResourcesContainerModel
	configRes              *config
	allGroups              []*collector.Group
	allGroupsPaths         []string
	allGroupsVMs           []*endpoints.VM
	groupToVMsListCache    map[*collector.Group][]*endpoints.VM
	servicePathToConnCache map[string]*netset.TransportSet
	// store references to groups/services objects from paths used in Fw rules
	groupPathsToObjects   map[string]*collector.Group
	servicePathsToObjects map[string]*collector.Service
}

func (p *NSXConfigParser) init() {
	p.configRes = &config{}
	p.groupPathsToObjects = map[string]*collector.Group{}
	p.servicePathsToObjects = map[string]*collector.Service{}
	p.groupToVMsListCache = map[*collector.Group][]*endpoints.VM{}
	p.servicePathToConnCache = map[string]*netset.TransportSet{}
}

func (p *NSXConfigParser) RunParser() error {
	logging.Debugf("started parsing the given NSX config")
	p.init()
	p.getVMs()    // get vms config
	p.getGroups() // get groups config
	p.removeVMsWithoutGroups()
	p.getDFW() // get distributed firewall config
	p.addPathsToDisplayNames()
	return nil
}

func (p *NSXConfigParser) removeVMsWithoutGroups() {
	toRemove := []*endpoints.VM{}
	for vm, groups := range p.configRes.GroupsPerVM {
		if len(groups) == 0 {
			logging.Debugf("ignoring VM without groups: %s", vm.Name())
			toRemove = append(toRemove, vm)
		}
	}
	for _, vm := range toRemove {
		delete(p.configRes.GroupsPerVM, vm)
		p.configRes.vms = slices.DeleteFunc(p.configRes.vms, func(v *endpoints.VM) bool { return v.ID() == vm.ID() })
		delete(p.configRes.vmsMap, vm.ID())
	}
}

func (p *NSXConfigParser) GetConfig() *config {
	return p.configRes
}

func (p *NSXConfigParser) vMsGroups() map[*endpoints.VM][]*collector.Group {
	groups := map[*endpoints.VM][]*collector.Group{}
	for _, g := range p.allGroups {
		vms := p.groupToVMsList(g)
		for _, vm := range vms {
			groups[vm] = append(groups[vm], g)
		}
	}
	for _, vm := range p.VMs() {
		if _, ok := groups[vm]; !ok {
			groups[vm] = nil
		}
	}
	return groups
}

func (p *NSXConfigParser) VMs() []*endpoints.VM {
	return p.configRes.vms
}

// update mapping from groups and services paths to their names
func (p *NSXConfigParser) addPathsToDisplayNames() {
	res := map[string]string{}
	for gPath, gObj := range p.groupPathsToObjects {
		res[gPath] = *gObj.DisplayName
	}
	for sPath, sObj := range p.servicePathsToObjects {
		res[sPath] = *sObj.DisplayName
	}
	p.configRes.Fw.SetPathsToDisplayNames(res)
}

func (p *NSXConfigParser) getGroups() {
	p.getAllGroups()
	p.configRes.GroupsPerVM = p.vMsGroups()
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
		vmObj.SetIPAddresses(p.rc.GetVirtualMachineAddresses(*vm.ExternalId))
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
	p.configRes.Fw = dfw.NewEmptyDFW(false) // TODO: what is global default?
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
			scope, _ := p.getEndpointsFromGroupsPaths(secPolicy.Scope, false)
			policyHasScope := !slices.Equal(secPolicy.Scope, []string{anyStr})

			rules := secPolicy.Rules
			for i := range rules {
				rule := &rules[i]
				r := p.getDFWRule(rule)
				r.scope = scope // scope from policy
				if !policyHasScope {
					// if policy scope is not configured, rule's scope takes effect
					r.scope, r.scopeGroups = p.getEndpointsFromGroupsPaths(rule.Scope, false)
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
	p.configRes.Fw.AddRule(r.srcVMs, r.dstVMs, r.srcGroups, r.dstGroups, r.scopeGroups, r.isAllSrcGroups, r.isAllDstGroups,
		r.conn, category, r.action, r.direction, r.ruleID, origRule, r.scope, r.secPolicyName, r.defaultRuleObj)
}

func (p *NSXConfigParser) getDefaultRule(secPolicy *collector.SecurityPolicy) *parsedRule {
	// from spec documentation:
	// The default rule that gets created will be a any-any rule and applied
	// to entities specified in the scope of the security policy.
	res := &parsedRule{}
	// scope - the list of group paths where the rules in this policy will get applied.
	scope := secPolicy.Scope
	vms, groups := p.getEndpointsFromGroupsPaths(scope, false)
	// rule applied as any-to-any only for ths VMs in the scope of the SecurityPolicy
	res.srcVMs = vms
	res.dstVMs = vms
	res.srcGroups = groups
	res.isAllSrcGroups = true
	res.dstGroups = groups
	res.isAllSrcGroups = true

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

	res.defaultRuleObj = secPolicy.DefaultRule
	return res
}

type parsedRule struct {
	srcVMs []*endpoints.VM
	dstVMs []*endpoints.VM
	// todo: In this stage we are not analyzing the complete expr, yet. In this stage we will only handle src and dst
	//       defined by groups, thus the following temp 4 fields
	srcGroups      []*collector.Group
	isAllSrcGroups bool
	dstGroups      []*collector.Group
	isAllDstGroups bool
	action         string
	conn           *netset.TransportSet
	direction      string
	ruleID         int
	scope          []*endpoints.VM
	// todo: scopeGroups tmp same as srcGroups and fields above
	scopeGroups    []*collector.Group
	secPolicyName  string
	defaultRuleObj *collector.FirewallRule
}

func (p *NSXConfigParser) getAllGroups() {
	// p.allGroupsVMs and p.allGroups and allGroupsPaths are written together
	vms := []*endpoints.VM{}
	groups := []*collector.Group{}
	groupsPaths := []string{}
	for i := range p.rc.DomainList {
		domainRsc := &p.rc.DomainList[i].Resources
		for j := range domainRsc.GroupList {
			group := &domainRsc.GroupList[j]
			vms = append(vms, p.groupToVMsList(group)...)
			groups = append(groups, group)
			groupsPaths = append(groupsPaths, *group.Path)
		}
	}
	p.allGroupsVMs = vms
	p.allGroups = groups
	p.allGroupsPaths = groupsPaths
}

func (p *NSXConfigParser) getEndpointsFromGroupsPaths(groupsPaths []string, exclude bool) ([]*endpoints.VM, []*collector.Group) {
	if slices.Contains(groupsPaths, anyStr) {
		// TODO: if a VM is not within any group, this should not include that VM?
		if exclude {
			return []*endpoints.VM{}, []*collector.Group{} // no group
		}
		return p.allGroupsVMs, p.allGroups // all groups
	}
	vms := []*endpoints.VM{}
	groups := []*collector.Group{}
	if exclude {
		groupsPaths = slices.DeleteFunc(slices.Clone(p.allGroupsPaths), func(p string) bool { return slices.Contains(groupsPaths, p) })
	}
	// TODO: support IP Addresses in groupsPaths
	for _, groupPath := range groupsPaths {
		thisGroupVMs, thisGroup := p.getGroupVMs(groupPath)
		vms = append(vms, thisGroupVMs...)
		groups = append(groups, thisGroup)
	}
	return vms, groups
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
	res.srcVMs, res.srcGroups = p.getEndpointsFromGroupsPaths(srcGroups, rule.SourcesExcluded)
	res.isAllSrcGroups = slices.Contains(srcGroups, anyStr)
	dstGroups := rule.DestinationGroups
	res.dstVMs, res.dstGroups = p.getEndpointsFromGroupsPaths(dstGroups, rule.DestinationsExcluded)
	res.isAllDstGroups = slices.Contains(dstGroups, anyStr)

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
			logging.Debugf("for rule %d, adding rule connection from Service: %s", *rule.RuleId, conn.String())
			res = res.Union(conn)
		}
	}
	conn := p.connectionFromServiceEntries(rule.ServiceEntries, rule)
	if conn != nil && !conn.IsEmpty() {
		logging.Debugf("for rule %d, adding rule connection from ServiceEntries: %s", *rule.RuleId, conn.String())
		res = res.Union(conn)
	}
	return res
}

// connectionFromService returns the set of connections from a service config within the given rule
func (p *NSXConfigParser) connectionFromService(servicePath string, rule *collector.Rule) *netset.TransportSet {
	if conn, ok := p.servicePathToConnCache[servicePath]; ok {
		return conn
	}
	service, ok := p.servicePathsToObjects[servicePath]
	if !ok {
		service = p.rc.GetService(servicePath)
		p.servicePathsToObjects[servicePath] = service
	}
	if service == nil {
		logging.Debugf("GetService failed to find service %s\n", servicePath)
		p.servicePathToConnCache[servicePath] = nil
		return nil
	}
	res := p.connectionFromServiceEntries(service.ServiceEntries, rule)
	logging.Debugf("service path: %s, conn: %s\n", servicePath, res.String())
	p.servicePathToConnCache[servicePath] = res
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
			logging.Debugf("ignoring service entry %s within rule id %d\n", serviceEntry.String(), *rule.RuleId)
		case conn == nil:
			logging.Debugf("warning: got nil connnection object for serviceEntry object")
		}
	}
	return res
}

func (p *NSXConfigParser) groupToVMsList(group *collector.Group) []*endpoints.VM {
	if vms, ok := p.groupToVMsListCache[group]; ok {
		return vms
	}
	ids := map[string]bool{}
	for i := range group.VMMembers {
		vm := &group.VMMembers[i]
		if vm.Id == nil { // use id instead of DisplayName, assuming matched to vm's external id
			logging.Debugf("in group %s - skipping VM member without id, at index %d", *group.DisplayName, i)
			continue
		}
		ids[*vm.Id] = true
	}
	for i := range group.VIFMembers {
		vif := &group.VIFMembers[i]
		if vif.OwnerVmId == nil {
			logging.Debugf("in group %s - skipping vif member without OwnerVmId, at index %d", *group.DisplayName, i)
			continue
		}
		if !ids[*vif.OwnerVmId] {
			logging.Debugf(
				"adding to group %s an OwnerVm of a VIFMember, while the VM is not in the group's VMMembers list, at index %d",
				*group.DisplayName, i)
		}
		ids[*vif.OwnerVmId] = true
	}
	for _, ip := range group.AddressMembers {
		vif := p.rc.GetVirtualNetworkInterfaceByAddress(string(ip))
		if vif == nil {
			logging.Debugf("in group %s - skipping IP member %s that has no VirtualNetworkInterface", *group.DisplayName, ip)
			continue
		}
		if vif.OwnerVmId == nil {
			logging.Debugf("in group %s - skipping VirtualNetworkInterface of IP address %s without OwnerVmId", *group.DisplayName, ip)
			continue
		}
		if !ids[*vif.OwnerVmId] {
			logging.Debugf("adding to group %s a VM with address %s, while the VM is not in the group's VMMembers list", *group.DisplayName, ip)
		}
		ids[*vif.OwnerVmId] = true
	}
	res := []*endpoints.VM{}
	for vmID := range ids {
		if vmObj, ok := p.configRes.vmsMap[vmID]; ok {
			res = append(res, vmObj)
		} else {
			// else: add warning that could not find that vm name in the config
			logging.Debugf("warning: could not find VM id %s in the parsed config, ignoring that VM for group members of group %s", vmID, *group.DisplayName)
		}
	}
	p.groupToVMsListCache[group] = res
	return res
}

func (p *NSXConfigParser) getGroupVMs(groupPath string) ([]*endpoints.VM, *collector.Group) {
	for i := range p.rc.DomainList {
		domainRsc := p.rc.DomainList[i].Resources
		for j := range domainRsc.GroupList {
			g := &domainRsc.GroupList[j]
			if g.Path != nil && groupPath == *g.Path {
				if _, ok := p.groupPathsToObjects[groupPath]; !ok {
					p.groupPathsToObjects[groupPath] = g
				}
				return p.groupToVMsList(g), g
			}
		}
	}
	return nil, nil // could not find given groupPath (add warning)
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
