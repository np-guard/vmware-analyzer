package data

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// logic for generating collector.Group objects, from Example objects

func createGroupFromVMMembers(groupName string, vmMembersNames []string) *collector.Group {
	newGroup := newGroupByExample(groupName)
	newGroup.VMMembers = createRealizedVirtualMachines(vmMembersNames)
	return newGroup
}

func createGroupFromExpr(groupName string, expr *ExampleExpr, allVMs []collector.VirtualMachine) *collector.Group {
	newGroup := newGroupByExample(groupName)
	newGroup.Expression = *expr.exampleExprToExpr()
	// populate group's VMMembers based on expr definition
	newGroup.VMMembers = virtualToRealizedVirtual(vmsOfExpr(allVMs, &newGroup.Expression))
	return newGroup
}

func createGroupOfIPAddresses(groupName string, addresses []nsx.IPElement) *collector.Group {
	newGroup := newGroupByExample(groupName)
	// creating a group with grouType IPAddress"IPAddress"
	newGroup.GroupType = append(newGroup.GroupType, nsx.GroupTypesIPAddress)
	newGroup.AddressMembers = addresses
	// following below section may not be necessary to add..
	newGroup.IPGroups = append(newGroup.IPGroups, nsx.PolicyGroupMemberDetails{Path: newGroup.Path, DisplayName: newGroup.DisplayName})
	ipAddrsExpr := &collector.IPAddressExpression{}
	ipAddrsExpr.ParentPath = newGroup.Path
	ipAddrsExpr.IpAddresses = addresses
	ipAddrsExpr.ResourceType = common.PointerTo(nsx.IPAddressExpressionResourceTypeIPAddressExpression)
	newGroup.Expression = append(newGroup.Expression, ipAddrsExpr)

	return newGroup
}

func createGroupByPathExpr(groupName string, paths []string, rc *collector.ResourcesContainerModel,
	segmentsByVMs map[string][]string) *collector.Group {
	newGroup := newGroupByExample(groupName)

	for _, path := range paths {
		found := false
		// extract elems from paths of segments/ other groups (todo: extend .. e.g. vif )
		// check other groups
		if g := rc.FindGroupByPath(path); g != nil {
			found = true
			// path to another group - import its members to this group
			importGroupMembersFromOtherGroup(newGroup, g)
		}
		// check segments
		if s := rc.GetSegment(path); s != nil && !found {
			found = true
			// path to a segment - update vm members by this segment
			// assunimg path is same as name key in the map segmentsByVMs
			if vms, ok := segmentsByVMs[path]; ok {
				newGroup.VMMembers = append(newGroup.VMMembers, createRealizedVirtualMachines(vms)...)
			}
			newGroup.Segments = append(newGroup.Segments, nsx.PolicyGroupMemberDetails{Path: &path, DisplayName: &path})
		}

		// if not found - internal err for this example generation
		if !found {
			logging.FatalErrorf("cannot generate example with GroupByPath - path %s was not found", path)
		}
	}

	// add the path expr
	pathExpr := &collector.PathExpression{}
	pathExpr.Paths = paths
	pathExpr.ResourceType = common.PointerTo(nsx.PathExpressionResourceTypePathExpression)
	newGroup.Expression = append(newGroup.Expression, pathExpr)
	return newGroup
}

func importGroupMembersFromOtherGroup(group, otherGroup *collector.Group) {
	group.VMMembers = append(group.VMMembers, otherGroup.VMMembers...)
	group.VIFMembers = append(group.VIFMembers, otherGroup.VIFMembers...)
	group.AddressMembers = append(group.AddressMembers, otherGroup.AddressMembers...)
	group.Segments = append(group.Segments, otherGroup.Segments...)
	group.SegmentPorts = append(group.SegmentPorts, otherGroup.SegmentPorts...)
	// todo: check if this is sufficient
}

// create a Group object with required name
func newGroupByExample(name string) *collector.Group {
	newGroup := &collector.Group{}
	newGroup.DisplayName = &name
	newGroup.Path = &name
	return newGroup
}

// create collector.Expression object from concise ExampleExpr requirements
func (exp *ExampleExpr) exampleExprToExpr() *collector.Expression {
	cond1 := exp.Cond1.toCollectorObject()
	if exp.Op == Nop {
		res := collector.Expression{cond1}
		return &res
	}
	res := make(collector.Expression, nonTrivialExprSize)
	res[0] = cond1
	expOp := collector.ConjunctionOperator{ConjunctionOperator: nsx.ConjunctionOperator{
		ResourceType: common.PointerTo(nsx.ConjunctionOperatorResourceTypeConjunctionOperator)}}
	conjOp := nsx.ConjunctionOperatorConjunctionOperatorAND
	if exp.Op == Or {
		conjOp = nsx.ConjunctionOperatorConjunctionOperatorOR
	}
	expOp.ConjunctionOperator.ConjunctionOperator = &conjOp
	res[1] = &expOp
	res[2] = exp.Cond2.toCollectorObject()
	return &res
}

func vmsOfExpressionElement(vmList []collector.VirtualMachine, c collector.ExpressionElement) []collector.VirtualMachine {
	var vmsRes []collector.VirtualMachine
	switch c1Expr := c.(type) {
	case *collector.Condition:
		vmsRes = vmsOfCondition(vmList, c1Expr)
	case *collector.NestedExpression:
		vmsRes = vmsOfExpr(vmList, &c1Expr.Expressions)
	default:
		logging.FatalErrorf("unsupported expr elem type: %v", c1Expr)
	}
	return vmsRes
}

func vmsOfExpr(vmList []collector.VirtualMachine, exp *collector.Expression) []collector.VirtualMachine {
	vmsCond1 := vmsOfExpressionElement(vmList, (*exp)[0])
	if len(*exp) == 1 {
		return vmsCond1
	}
	// len(*exp) is 3
	vmsCond2 := vmsOfExpressionElement(vmList, (*exp)[2])
	res := []collector.VirtualMachine{}
	conj := (*exp)[1].(*collector.ConjunctionOperator)
	if *conj.ConjunctionOperator.ConjunctionOperator == nsx.ConjunctionOperatorConjunctionOperatorOR {
		// union of vmsCond1 and vmsCond2
		res = append(res, vmsCond1...)
		for i := range vmsCond2 {
			if !vmInList(res, &vmsCond2[i]) {
				res = append(res, vmsCond2[i])
			}
		}
	} else { // intersection
		for i := range vmsCond1 {
			if vmInList(vmsCond2, &vmsCond1[i]) {
				res = append(res, vmsCond1[i])
			}
		}
	}
	return res
}

func tagInTags(vmTags []nsx.Tag, tag string) bool {
	for _, tagOfVM := range vmTags {
		if tag == tagOfVM.Tag {
			return true
		}
	}
	return false
}

func vmsOfCondition(vmList []collector.VirtualMachine, cond *collector.Condition) []collector.VirtualMachine {
	var resTagNotExist bool
	if *cond.Operator == nsx.ConditionOperatorNOTEQUALS {
		resTagNotExist = true
	}
	return getVMsOfTagOrNotTag(vmList, *cond.Value, resTagNotExist)
}

func vmInList(vmList []collector.VirtualMachine, vm *collector.VirtualMachine) bool {
	for i := range vmList {
		if vmList[i].Name() == vm.Name() {
			return true
		}
	}
	return false
}

func virtualToRealizedVirtual(origList []collector.VirtualMachine) []collector.RealizedVirtualMachine {
	res := make([]collector.RealizedVirtualMachine, len(origList))
	for i := range origList {
		realizedVM := collector.RealizedVirtualMachine{}
		realizedVM.DisplayName = origList[i].DisplayName
		realizedVM.Id = origList[i].ExternalId
		res[i] = realizedVM
	}
	return res
}

// todo: should be generalized and moved elsewhere?
func getVMsOfTagOrNotTag(vmList []collector.VirtualMachine, tag string, resTagNotExist bool) []collector.VirtualMachine {
	res := []collector.VirtualMachine{}
	for i := range vmList {
		vm := vmList[i]
		tagExist := tagInTags(vm.Tags, tag)
		if !tagExist && resTagNotExist {
			res = append(res, vm)
		} else if tagExist && !resTagNotExist {
			res = append(res, vm)
		}
	}
	return res
}
