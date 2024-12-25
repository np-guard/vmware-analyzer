package model

import (
	"fmt"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	resources "github.com/np-guard/vmware-analyzer/pkg/model/generated"
)

type AbstractModelSyn struct {
	epToAtonicGroups   map[*endpoints.VM][]*collector.Group
	epToEntitiesGroups map[*endpoints.VM][]*collector.Group
	epToTags           map[*endpoints.VM]*[]resources.Tag
}

func (p *NSXConfigParser) CollectVMTags(recourses *collector.ResourcesContainerModel) {
	abstractModelSyn := AbstractModelSyn{
		epToAtonicGroups   :map[*endpoints.VM][]*collector.Group{},
		epToEntitiesGroups :map[*endpoints.VM][]*collector.Group{},
		epToTags           :map[*endpoints.VM]*[]resources.Tag{},
	
	}
	for i := range recourses.VirtualMachineList {
		vmResource := recourses.VirtualMachineList[i]
		vm := p.configRes.vmsMap[*vmResource.ExternalId]
		abstractModelSyn.epToTags[vm] = &vmResource.Tags
	}
	for _, g := range p.groups {
		fmt.Printf("group %s %s: ",*g.DisplayName, g.Description())
		vms := p.groupToVMsList(g)
		for _, vm := range vms {
			fmt.Printf("%s, ", vm.Name())
			if g.Expression != nil {
				abstractModelSyn.epToEntitiesGroups[vm] = append(abstractModelSyn.epToEntitiesGroups[vm], g)
			} else {
				abstractModelSyn.epToAtonicGroups[vm] = append(abstractModelSyn.epToAtonicGroups[vm], g)
			}
		}
		fmt.Println("")
	}

}

