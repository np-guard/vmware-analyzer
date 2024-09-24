package model

import (
	"os"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
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
	for _, vm := range p.rc.VirtualMachineList {
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
	for _, domain := range p.rc.DomainList {
		domainRsc := domain.Resources
		for _, secPolicy := range domainRsc.SecurityPolicyList {
			if secPolicy.Category == nil {
				continue // skip secPolicy with nil category (add warning)
			}
			category := *secPolicy.Category
			/*secPolicyName := secPolicy.DisplayName
			secPolicyId := secPolicy.Id
			scope := secPolicy.Scope // support ANY at first*/
			// more fields to consider: sequence_number , stateful,tcp_strict, unique_id

			rules := secPolicy.Rules
			for _, rule := range rules {
				r := p.getDFWRule(rule.Rule)
				p.configRes.fw.AddRule(r.srcVMs, r.dstVMs, r.conn, category, r.action, r.direction, &rule.Rule)
			}
		}
	}
}

type parsedRule struct {
	srcVMs    []*endpoints.VM
	dstVMs    []*endpoints.VM
	action    string
	conn      *connection.Set
	direction string
}

func (p *NSXConfigParser) allGroups() (res []*endpoints.VM) {
	if len(p.allGroupsVMs) > 0 {
		return p.allGroupsVMs
	}
	for _, domain := range p.rc.DomainList {
		domainRsc := domain.Resources
		for _, g := range domainRsc.GroupList {

			res = append(res, p.membersToVMsList(g.Members)...)
		}
	}
	p.allGroupsVMs = res
	return res
}

func (p *NSXConfigParser) getSrcOrDstEndpoints(groupsPaths []string) (res []*endpoints.VM) {
	if slices.Contains(groupsPaths, anyStr) {
		// TODO: if a VM is not within any group, this should not include that VM?
		return p.allGroups() // all groups
	}
	// TODO: support IP Addresses in groupsPaths
	for _, groupPath := range groupsPaths {
		res = append(res, p.getGroupVMs(groupPath)...)
	}
	return res
}

func (p *NSXConfigParser) getDFWRule(rule nsx.Rule) *parsedRule {
	if rule.Action == nil {
		return nil // skip rule without action (Add warning)
	}

	res := &parsedRule{}
	srcGroups := rule.SourceGroups // paths of the source groups
	// If set to true, the rule gets applied on all the groups that are NOT part of
	// the source groups. If false, the rule applies to the source groups
	// TODO: handle excluded fields
	// srcExclude := rule.SourcesExcluded
	res.srcVMs = p.getSrcOrDstEndpoints(srcGroups)
	dstGroups := rule.DestinationGroups
	res.dstVMs = p.getSrcOrDstEndpoints(dstGroups)

	res.action = string(*rule.Action)
	res.conn = p.getRuleConnections(rule)
	res.direction = string(rule.Direction)
	return res
}

func (p *NSXConfigParser) getRuleConnections(rule nsx.Rule) *connection.Set {

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
		return connection.All()
	}
	res := connection.None()
	for _, s := range rule.Services {
		conn := p.connectionFromService(s)
		res = res.Union(conn)
	}

	return res
}

func (p *NSXConfigParser) connectionFromService(servicePath string) *connection.Set {
	// TODO: temporary work around, should be implemented
	if strings.Contains(servicePath, "ICMP") { // example: "/infra/services/ICMP-ALL"
		return connection.ICMPConnection(0, 255, 0, 255)
	}
	return connection.None()
}

func (p *NSXConfigParser) membersToVMsList(members []collector.RealizedVirtualMachine) (res []*endpoints.VM) {
	for _, vm := range members {
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
	for _, domain := range p.rc.DomainList {
		domainRsc := domain.Resources
		for _, g := range domainRsc.GroupList {
			if g.Path != nil && groupPath == *g.Path {
				return p.membersToVMsList(g.Members)
			}
		}
	}
	return nil // could not find given groupPath (add warning)
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// comments for later

//scope := secPolicy.Scope // support ANY at first
// more fields to consider: sequence_number , stateful,tcp_strict, unique_id
/*
	If there are multiple policies with the same
		// sequence number then their order is not deterministic. If a specific order of
		// policies is desired, then one has to specify unique sequence numbers or use the
		// POST request on the policy entity with a query parameter action=revise to let
		// the framework assign a sequence number. The value of sequence number must be
		// between 0 and 999,999.
*/
