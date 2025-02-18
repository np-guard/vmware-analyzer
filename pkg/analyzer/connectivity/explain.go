package connectivity

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func (c ConnMap) GetExplanationPerConnection(srcVM, dstVM string, inputConn *netset.TransportSet) (isAllowed bool, ingress, egress []int) {
	logging.Debugf("GetExplanationPerConnection")
	entry := c.getEntryPerEndpoints(srcVM, dstVM)
	if entry == nil {
		return false, nil, nil
	}
	if inputConn.IsSubset(entry.DetailedConn.Conn) {
		isAllowed = true
	}
	for _, ingressEntry := range entry.DetailedConn.ExplanationObj.IngressExplanations {
		if !(inputConn.Intersect(ingressEntry.Conn)).IsEmpty() {
			ingress = append(ingress, ingressEntry.RuleID)
		}
	}
	for _, egressEntry := range entry.DetailedConn.ExplanationObj.EgressExplanations {
		if !(inputConn.Intersect(egressEntry.Conn)).IsEmpty() {
			egress = append(egress, egressEntry.RuleID)
		}
	}
	return isAllowed, ingress, egress
}

func (c ConnMap) genExplanationOutput() string {
	return fmt.Sprintf("\n\nExplanation section:\n%s", c.fullOutputWithExplanations())
}

func (c ConnMap) fullOutputWithExplanations() string {
	asSlice := c.toSlice()
	return common.SortedJoinCustomStrFuncSlice(asSlice, func(c *connMapEntry) string { return c.fullExplanationString() }, common.ShortSep)
}

func (c connMapEntry) fullExplanationString() string {
	header := fmt.Sprintf("src: %s, dst: %s", c.Src.Name(), c.Dst.Name())
	deniedConn := netset.AllTransports().Subtract(c.DetailedConn.Conn)
	allowedConns := fmt.Sprintf("allowed connections: %s, rules details:\n%s",
		c.DetailedConn.Conn.String(), c.DetailedConn.DetailedExplanationString(c.DetailedConn.Conn))
	deniedConns := fmt.Sprintf("denied connections: %s, rules details:\n%s",
		deniedConn.String(), c.DetailedConn.DetailedExplanationString(deniedConn))
	return strings.Join([]string{header, allowedConns, deniedConns}, "\n")
}
