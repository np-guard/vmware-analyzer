package dfw

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration/topology"
)

// RuleEndpoints captures various representations and properties of nsx rule endpoints,
// configured as original src/dst/scope attributes
type RuleEndpoints struct {
	VMs         []topology.Endpoint
	Groups      []*collector.Group
	IsAllGroups bool
	Blocks      []*topology.RuleIPBlock
	IsExclude   bool
}

// topology.Endpoint
func (r *RuleEndpoints) ContainsEndpoint(e topology.Endpoint) bool {
	if slices.Contains(r.VMs, e) {
		return true
	}
	for _, b := range r.Blocks {
		if slices.Contains(b.ExternalIPs, e) {
			return true
		}
	}
	return false
	// todo: extend to segments ?
	// todo: check with ip sub ranges ?
}

func (r *RuleEndpoints) ShortStr() string {
	extIPs := []string{}
	for _, e := range r.Blocks {
		extIPs = append(extIPs, e.OriginalIP)
	}

	return common.JoinStringifiedSlice(r.VMs, common.CommaSeparator) + strings.Join(extIPs, common.CommaSeparator)
}

func (r *RuleEndpoints) String() string {
	vmsStr := fmt.Sprintf("VMs: %s", common.JoinStringifiedSlice(r.VMs, common.CommaSeparator))
	groupsStr := fmt.Sprintf("Groups: %s", common.JoinStringifiedSlice(r.Groups, common.CommaSeparator))
	blocksStr := fmt.Sprintf("Blocks:\n %s", common.JoinStringifiedSlice(r.Blocks, common.NewLine))
	return strings.Join([]string{vmsStr, groupsStr, blocksStr}, common.NewLine)
}
