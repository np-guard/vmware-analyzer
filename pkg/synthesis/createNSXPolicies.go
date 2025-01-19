package synthesis

import (
	"fmt"
	"slices"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
	"github.com/np-guard/vmware-analyzer/pkg/symbolicexpr"
)

func toNSXPolicies(model *AbstractModelSyn) []collector.SecurityPolicy {

	category := data.Category{
		Name:         "default",
		CategoryType: "Application",
		Rules:        []data.Rule{},
	}
	addNewRule := func(description string) *data.Rule {
		rule := newRule(1000+len(category.Rules), description)
		category.Rules = append(category.Rules, rule)
		return &category.Rules[len(category.Rules)-1]
	}
	for _, p := range model.policy {
		for _, ob := range p.outbound {
			for _, p := range ob.allowOnlyRulePaths {
				srcGroup, dstGroup, services := toGroupsAndService(model, p)
				rule := addNewRule(p.String())
				rule.Source = srcGroup
				rule.Dest = dstGroup
				rule.Services = services
				rule.Direction = "OUT"
			}
		}
		for _, ib := range p.inbound {
			for _, p := range ib.allowOnlyRulePaths {
				srcGroup, dstGroup, services := toGroupsAndService(model, p)
				rule := addNewRule(p.String())
				rule.Source = srcGroup
				rule.Dest = dstGroup
				rule.Services = services
				rule.Direction = "IN"
			}
		}
	}
	return data.ToPoliciesList([]data.Category{category})
}

func newRule(id int, description string) data.Rule {
	return data.Rule{
		Name:        fmt.Sprintf("ruleName_%d", id),
		ID:          id,
		Action:      data.Allow,
		Description: description,
	}
}

func toGroupsAndService(model *AbstractModelSyn, p *symbolicexpr.SymbolicPath) (src, dst string, service []string) {
	vmLabels,labelsVMs := vmLabels(model)
	fmt.Printf( "%s:", p.String())
	srcVMs := conjVMs(p.Src, model.vms,vmLabels,labelsVMs)
	dstVMs := conjVMs(p.Dst, model.vms,vmLabels,labelsVMs)
	for _, v := range srcVMs{
		fmt.Printf( "%s, ", v.Name())
	}
	fmt.Printf( " to ")
	for _, v := range dstVMs{
		fmt.Printf( "%s, ", v.Name())
	}
	fmt.Println( "")
	// return vmLabels[srcVMs[0]][0], vmLabels[dstVMs[0]][0], []string{"ANY"}
	return "vmLabels[srcVMs[0]][0]", "vmLabels[dstVMs[0]][0]", []string{"ANY"}
}

func vmLabels(model *AbstractModelSyn) (map[*endpoints.VM][]string, map[string][]*endpoints.VM) {
	vmLabels := map[*endpoints.VM][]string{}
	labelsVMs := map[string][]*endpoints.VM{}
	for _, vm := range model.vms {
		if len(model.epToGroups[vm]) == 0 {
			continue
		}
		for _, group := range model.epToGroups[vm] {
			label, _ := symbolicexpr.NewAtomicTerm(group, group.Name(), false).AsSelector()
			vmLabels[vm] = append(vmLabels[vm], label)
			labelsVMs[label] = append(labelsVMs[label], vm)
		}
	}
	return vmLabels, labelsVMs
}

func conjVMs(
	con symbolicexpr.Conjunction,
	allVMs []*endpoints.VM,
	vmLabels map[*endpoints.VM][]string,
	labelsVMs map[string][]*endpoints.VM,
) []*endpoints.VM {
	vms := slices.Clone(allVMs)
	for _, atom := range con {
		if atom.IsTautology() {
			continue
		}
		label, not := atom.AsSelector()
		atomVMs := labelsVMs[label]
		if not {
			atomVMs = endpoints.Subtract(allVMs, atomVMs)
		}
		vms = endpoints.Intersection(vms, atomVMs)
	}
	return vms
}

// var codeToProtocol = map[int]core.Protocol{netset.UDPCode: core.ProtocolUDP, netset.TCPCode: core.ProtocolTCP}
// var boolToOperator = map[bool]meta.LabelSelectorOperator{false: meta.LabelSelectorOpExists, true: meta.LabelSelectorOpDoesNotExist}

// func pointerTo[T any](t T) *T {
// 	return &t
// }

// func toPolicyPorts(conn *netset.TransportSet) ([]networking.NetworkPolicyPort, bool) {
// 	ports := []networking.NetworkPolicyPort{}
// 	tcpUDPSet := conn.TCPUDPSet()
// 	if tcpUDPSet.IsEmpty() {
// 		return nil, true
// 	}
// 	if tcpUDPSet.IsAll() {
// 		return nil, false
// 	}
// 	partitions := tcpUDPSet.Partitions()
// 	for _, partition := range partitions {
// 		protocols := partition.S1.Elements()
// 		portRanges := partition.S3
// 		for _, portRange := range portRanges.Intervals() {
// 			var portPointer *intstr.IntOrString
// 			var endPortPointer *int32
// 			if portRange.Start() != netp.MinPort || portRange.End() != netp.MaxPort {
// 				port := intstr.FromInt(int(portRange.Start()))
// 				portPointer = &port
// 				if portRange.End() != portRange.Start() {
// 					//nolint:gosec // port should fit int32:
// 					endPort := int32(portRange.End())
// 					endPortPointer = &endPort
// 				}
// 			}
// 			for _, protocolCode := range protocols {
// 				ports = append(ports, networking.NetworkPolicyPort{
// 					Protocol: pointerTo(codeToProtocol[int(protocolCode)]),
// 					Port:     portPointer,
// 					EndPort:  endPortPointer})
// 			}
// 			if slices.Contains(protocols, netset.TCPCode) && slices.Contains(protocols, netset.UDPCode) {
// 				ports = append(ports, networking.NetworkPolicyPort{Protocol: pointerTo(core.ProtocolSCTP), Port: portPointer, EndPort: endPortPointer})
// 			}
// 		}
// 	}
// 	return ports, false
// }
