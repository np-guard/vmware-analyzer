package model

import (
	"os"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/dfw"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	nsx "github.com/np-guard/vmware-analyzer/pkg/model/generated"
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
	file      string
	rc        *collector.ResourcesContainerModel
	configRes *config
}

func (p *NSXConfigParser) runParser() error {
	p.configRes = &config{}
	p.getVMs() // get vms config
	p.getDFW() // get distributed firewall config
	return nil
}

func (p *NSXConfigParser) getConfig() *config {
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
			category := secPolicy.Category
			/*secPolicyName := secPolicy.DisplayName
			secPolicyId := secPolicy.Id
			scope := secPolicy.Scope // support ANY at first*/
			// more fields to consider: sequence_number , stateful,tcp_strict, unique_id

			rules := secPolicy.Rules
			for _, rule := range rules {
				r := p.getDFWRule(rule)
				p.configRes.fw.AddRule(r.srcVMs, r.dstVMs, nil, *category, r.action)

			}

		}

	}
}

type parsedRule struct {
	srcVMs []*endpoints.VM
	dstVMs []*endpoints.VM
	action string
}

func (p *NSXConfigParser) getSrcOrDstEndpoints(groupsPaths []string) (res []*endpoints.VM) {
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
	// srcExclude := rule.SourcesExcluded
	res.srcVMs = p.getSrcOrDstEndpoints(srcGroups)
	dstGroups := rule.DestinationGroups
	res.dstVMs = p.getSrcOrDstEndpoints(dstGroups)
	res.action = string(*rule.Action)
	return res
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
