package configuration

import (
	"os"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
	"github.com/np-guard/vmware-analyzer/pkg/logging"

	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

const (
	anyStr = "ANY" // ANY can specify any service or any src/dst in DFW rules
)

func NewNSXConfigParserFromFile(fileName string) (*nsxConfigParser, error) {
	res := &nsxConfigParser{file: fileName}

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

func newNSXConfigParserFromResourcesContainer(rc *collector.ResourcesContainerModel) *nsxConfigParser {
	return &nsxConfigParser{
		rc: rc,
	}
}

type nsxConfigParser struct {
	file                   string
	rc                     *collector.ResourcesContainerModel
	configRes              *Config
	allGroups              []*collector.Group
	allGroupsPaths         []string
	groupToVMsListCache    map[*collector.Group][]topology.Endpoint
	servicePathToConnCache map[string]*netset.TransportSet
	// store references to groups/services objects from paths used in Fw rules
	groupPathsToObjects   map[string]*collector.Group
	servicePathsToObjects map[string]*collector.Service
}

func (p *nsxConfigParser) init() {
	p.configRes = &Config{origNSXResources: p.rc}
	p.groupPathsToObjects = map[string]*collector.Group{}
	p.servicePathsToObjects = map[string]*collector.Service{}
	p.groupToVMsListCache = map[*collector.Group][]topology.Endpoint{}
	p.servicePathToConnCache = map[string]*netset.TransportSet{}
}

func (p *nsxConfigParser) runParser() error {
	logging.Debugf("started parsing the given NSX config")

	p.init() // initialize relevant maps objects

	// the parsing of relevant NSX objects is done here
	p.storeParsedVMs()    // get vms config
	p.storeParsedGroups() // get groups config
	p.removeVMsWithoutGroups()
	if err := p.getTopology(); err != nil {
		return err
	}
	p.storeParsedSegments() // get NSX segments config

	p.storeParsedDFW() // get distributed firewall config

	// additional mappings for more details on log and config fields
	p.addPathsToDisplayNames()
	return nil
}

// storeParsedVMs assigns the parsed VM objects from the NSX resources container into the res config object
func (p *nsxConfigParser) storeParsedVMs() {
	p.configRes.VMsMap = map[string]topology.Endpoint{}
	for i := range p.rc.VirtualMachineList {
		vm := &p.rc.VirtualMachineList[i]
		if vm.DisplayName == nil || vm.ExternalId == nil {
			// skip vm without name
			logging.Debugf("warning: skipped vm without name/uid at index %d", i)
			continue
		}
		vmObj := topology.NewVM(*vm.DisplayName, *vm.ExternalId)
		vmObj.SetIPAddresses(p.rc.GetVirtualMachineAddresses(*vm.ExternalId))
		for _, tag := range vm.Tags {
			vmObj.AddTag(tag.Tag)
			// currently ignoring tag scope
			if tag.Scope != "" {
				logging.Debugf("warning: ignoring tag scope for VM %s, tag: %s, scope: %s", *vm.DisplayName, tag.Tag, tag.Scope)
			}
		}
		p.configRes.VMs = append(p.configRes.VMs, vmObj)
		p.configRes.VMsMap[vmObj.ID()] = vmObj
	}
}

func (p *nsxConfigParser) storeParsedSegments() {
	for i := range p.rc.SegmentList {
		segment := &p.rc.SegmentList[i]
		vms := p.configRes.GetVMs(p.rc.GetVMsOfSegment(segment))
		p.configRes.segments = append(p.configRes.segments, topology.NewSegmentDetails(segment, vms))
	}
}

func (p *nsxConfigParser) removeVMsWithoutGroups() {
	toRemove := []topology.Endpoint{}
	for vm, groups := range p.configRes.GroupsPerVM {
		if len(groups) == 0 {
			addressInfo := ""
			if vm.IPAddressesStr() != "" {
				addressInfo = ", address: " + vm.IPAddressesStr()
			}
			logging.Debugf("ignoring VM without groups: %s%s", vm.Name(), addressInfo)
			toRemove = append(toRemove, vm)
		}
	}
	for _, vm := range toRemove {
		delete(p.configRes.GroupsPerVM, vm)
		p.configRes.VMs = slices.DeleteFunc(p.configRes.VMs, func(v topology.Endpoint) bool { return v.ID() == vm.ID() })
		delete(p.configRes.VMsMap, vm.ID())
	}
}

func (p *nsxConfigParser) getConfig() *Config {
	return p.configRes
}

func (p *nsxConfigParser) vMsGroups() map[topology.Endpoint][]*collector.Group {
	groups := map[topology.Endpoint][]*collector.Group{}
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

func (p *nsxConfigParser) VMs() []topology.Endpoint {
	return p.configRes.VMs
}

// update mapping from groups and services paths to their names
func (p *nsxConfigParser) addPathsToDisplayNames() {
	res := map[string]string{}
	for gPath, gObj := range p.groupPathsToObjects {
		res[gPath] = *gObj.DisplayName
	}
	for sPath, sObj := range p.servicePathsToObjects {
		res[sPath] = *sObj.DisplayName
	}
	for _, block := range p.configRes.Topology.AllRuleIPBlocks {
		res[block.OriginalIP] = block.OriginalIP
	}
	p.configRes.FW.SetPathsToDisplayNames(res)
}

func (p *nsxConfigParser) storeParsedGroups() {
	p.getAllGroups()
	p.configRes.Groups = p.allGroups
	p.configRes.GroupsPerVM = p.vMsGroups()
}

func (p *nsxConfigParser) storeParsedDFW() {
	p.configRes.FW = dfw.NewEmptyDFW()
	for i := range p.rc.DomainList {
		domainRsc := p.rc.DomainList[i].Resources
		for j := range domainRsc.SecurityPolicyList {
			secPolicy := &domainRsc.SecurityPolicyList[j]
			if secPolicy.Category == nil {
				continue // skip secPolicy with nil category (add warning)
			}
			category := *secPolicy.Category
			// more fields to consider: sequence_number , stateful,tcp_strict, unique_id

			// This policy scope will take precedence over rule level scope (if it specifies an actual scope and not "ANY")
			policyScope := dfw.RuleEndpoints{}
			policyScope.VMs, policyScope.Groups = p.getEndpointsFromScopePaths(secPolicy.Scope)
			policyScope.IsAllGroups = slices.Equal(secPolicy.Scope, []string{anyStr})
			policyHasScope := !policyScope.IsAllGroups

			rules := secPolicy.Rules
			for i := range rules {
				rule := &rules[i]
				r := p.getDFWRule(rule)
				r.scope = policyScope
				if !policyHasScope {
					// if policy scope is not configured, rule's scope takes effect
					r.scope.IsAllGroups = slices.Equal(rule.Scope, []string{anyStr})
					r.scope.VMs, r.scope.Groups = p.getEndpointsFromScopePaths(rule.Scope)
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
					defaultRule.scope = policyScope // default-rule is relevant to a scoped policy only
					defaultRule.secPolicyName = *secPolicy.DisplayName
					p.addFWRule(defaultRule, category, nil)
				}
			}
		}
	}
}

func (p *nsxConfigParser) addFWRule(r *parsedRule, category string, origRule *collector.Rule) {
	p.configRes.FW.AddRule(&r.src, &r.dst, &r.scope,
		r.conn, category, r.action, r.direction, r.ruleID, origRule, r.secPolicyName, r.defaultRuleObj)
}

func (p *nsxConfigParser) getDefaultRule(secPolicy *collector.SecurityPolicy) *parsedRule {
	// from spec documentation:
	// The default rule that gets created will be a any-any rule and applied
	// to entities specified in the scope of the security policy.
	res := &parsedRule{}
	// scope - the list of group paths where the rules in this policy will get applied.
	scope := secPolicy.Scope
	vms, groups := p.getEndpointsFromScopePaths(scope)
	// rule applied as any-to-any only for ths VMs in the scope of the SecurityPolicy
	res.src.VMs = vms
	res.dst.VMs = vms
	res.src.Groups = groups
	res.src.IsAllGroups = true
	res.dst.Groups = groups
	res.dst.IsAllGroups = true

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
	src            dfw.RuleEndpoints
	dst            dfw.RuleEndpoints
	scope          dfw.RuleEndpoints
	action         string
	conn           *netset.TransportSet
	direction      string
	ruleID         int
	secPolicyName  string
	defaultRuleObj *collector.FirewallRule
}

func (p *nsxConfigParser) getAllGroups() {
	// p.allGroups and allGroupsPaths are written together
	for i := range p.rc.DomainList {
		domainRsc := &p.rc.DomainList[i].Resources
		for j := range domainRsc.GroupList {
			group := &domainRsc.GroupList[j]
			p.allGroups = append(p.allGroups, group)
			p.allGroupsPaths = append(p.allGroupsPaths, *group.Path)
		}
	}
}

// todo: delete this method, use getEndpointsFromGroupsPaths() directly
func (p *nsxConfigParser) getEndpointsFromScopePaths(groupsPaths []string) ([]topology.Endpoint, []*collector.Group) {
	if slices.Contains(groupsPaths, anyStr) {
		// in scope - "any" are all the vms
		return p.configRes.VMs, p.allGroups // all endpoints and groups
	}
	ruleEndpoints := p.getEndpointsFromGroupsPaths(groupsPaths, false)
	return ruleEndpoints.VMs, ruleEndpoints.Groups
}

func (p *nsxConfigParser) getEndpointsFromGroupsPaths(groupsPaths []string, exclude bool) *dfw.RuleEndpoints {
	res := &dfw.RuleEndpoints{}
	if slices.Contains(groupsPaths, anyStr) {
		// TODO: if a VM is not within any group, this should not include that VM?
		if exclude {
			return res // no group
		}
		return &dfw.RuleEndpoints{VMs: p.configRes.VMs, Groups: p.allGroups, IsAllGroups: true} // all groups
	}
	// cidrs/ip addresses are given as input groupsPaths, and are not expected to be in p.allGroupsPaths, thus filtering them into ips slice
	ips := slices.DeleteFunc(slices.Clone(groupsPaths), func(path string) bool { return slices.Contains(p.allGroupsPaths, path) })
	// remaining actual groups paths strings  are expected to be in p.allGroupsPaths, thus filtering them into groupsPaths slice
	groupsPaths = slices.DeleteFunc(slices.Clone(groupsPaths), func(path string) bool { return !slices.Contains(p.allGroupsPaths, path) })

	if exclude {
		if len(ips) > 0 {
			// TODO: support excluded with ip ranges as well
			logging.Debugf("Rule with IPs and Excluded is not supported. ignoring the following IPs\n%s",
				strings.Join(ips, common.CommaSeparator))
		}
	} else {
		for _, ip := range ips {
			if ruleBlock := p.configRes.Topology.AllRuleIPBlocks[ip]; ruleBlock != nil {
				res.VMs = append(res.VMs, ruleBlock.VMs...)
				res.VMs = append(res.VMs, ruleBlock.ExternalIPs...)
				res.Blocks = append(res.Blocks, ruleBlock)
			}
		}
	}

	res.Groups = make([]*collector.Group, len(groupsPaths))
	for i, groupPath := range groupsPaths {
		thisGroupVMs, thisGroup := p.getGroupVMs(groupPath)
		res.VMs = append(res.VMs, thisGroupVMs...)
		res.Groups[i] = thisGroup
	}

	if exclude {
		vms := topology.Subtract(p.configRes.VMs, res.VMs) // vms contain the actual remaining vms after exclude operation
		res.VMs = vms
		res.IsExclude = true // todo: to be used by synthesis (the combination of res.Groups & res.IsExclude)
	}

	res.VMs = common.SliceCompact(res.VMs)
	return res
}

// type *collector.FirewallRule is deprecated but used to collect default rule per securityPolicy
/*func (p *NSXConfigParser) getDFWRule(rule *collector.FirewallRule) *parsedRule {

}*/

func (p *nsxConfigParser) getDFWRule(rule *collector.Rule) *parsedRule {
	if rule.Action == nil {
		return nil // skip rule without action (Add warning)
	}

	res := &parsedRule{}
	srcGroups := rule.SourceGroups // paths of the source groups
	dstGroups := rule.DestinationGroups
	// If set to true, the rule gets applied on all the groups that are NOT part of
	// the source groups. If false, the rule applies to the source groups
	// TODO: handle excluded fields
	// srcExclude := rule.SourcesExcluded
	res.src = *p.getEndpointsFromGroupsPaths(srcGroups, rule.SourcesExcluded)
	res.dst = *p.getEndpointsFromGroupsPaths(dstGroups, rule.DestinationsExcluded)

	res.action = string(*rule.Action)
	res.conn = p.getRuleConnections(rule)
	res.direction = string(rule.Direction)
	res.ruleID = *rule.RuleId
	return res
}

func (p *nsxConfigParser) getRuleConnections(rule *collector.Rule) *netset.TransportSet {
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
		// currently, ignoring services "ANY", if ServiceEntries is not empty..
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
func (p *nsxConfigParser) connectionFromService(servicePath string, rule *collector.Rule) *netset.TransportSet {
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
func (p *nsxConfigParser) connectionFromServiceEntries(serviceEntries collector.ServiceEntries, rule *collector.Rule) *netset.TransportSet {
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

func (p *nsxConfigParser) groupToVMsList(group *collector.Group) []topology.Endpoint {
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
	res := []topology.Endpoint{}
	for vmID := range ids {
		if vmObj, ok := p.configRes.VMsMap[vmID]; ok {
			res = append(res, vmObj)
		} else {
			// else: add warning that could not find that vm name in the config
			logging.Debugf(
				"warning: could not find VM id %s in the parsed config, ignoring that VM for group members of group %s",
				vmID, *group.DisplayName)
		}
	}
	p.groupToVMsListCache[group] = res
	return res
}

func (p *nsxConfigParser) getGroupVMs(groupPath string) ([]topology.Endpoint, *collector.Group) {
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
