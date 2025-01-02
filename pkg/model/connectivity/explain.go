package connectivity

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func (c ConnMap) GetExplanationPerConnection(srcVM, dstVM string, inputConn *netset.TransportSet) (isAllowed bool, ingress []int, egress []int) {
	logging.Debugf("GetExplanationPerConnection")
	for src, srcMap := range c {
		if src.Name() != srcVM {
			continue
		}
		logging.Debugf("src.Name: %s, srcVM: %s", src.Name(), srcVM)
		for dst, connEntry := range srcMap {
			if dst.Name() != dstVM {
				continue
			}
			logging.Debugf("dst.Name: %s, dst: %s", dst.Name(), dstVM)
			logging.Debugf("inputConn: %s ,connEntry.Conn: %s, res: %t ", inputConn.String(), connEntry.Conn.String(), inputConn.IsSubset(connEntry.Conn))
			// assuming inputConn is fully contained in allowed/denied connection (inputConn should be specific connection of protocol and port)
			// todo: add warning/err/other handling if this is not the case
			if inputConn.IsSubset(connEntry.Conn) {
				isAllowed = true
			}
			for _, ingressEntry := range connEntry.ExplanationObj.IngressExplanations {
				logging.Debugf("inputConn: %s, ingressEntry.Conn: %s", inputConn.String(), ingressEntry.Conn.String())
				if !(inputConn.Intersect(ingressEntry.Conn)).IsEmpty() {
					ingress = append(ingress, ingressEntry.Rule)
					logging.Debugf("append")
				}
			}
			for _, egressEntry := range connEntry.ExplanationObj.EgressExplanations {
				if !(inputConn.Intersect(egressEntry.Conn)).IsEmpty() {
					egress = append(egress, egressEntry.Rule)
				}
			}

		}
	}
	return isAllowed, ingress, egress
}

func (c ConnMap) genExplanationOutput() string {
	return fmt.Sprintf("\n\nExplanation section:\n%s", c.fullOutputWithExplanations())
}

func (c ConnMap) fullOutputWithExplanations() string {
	asSlice := c.toSlice()
	return common.SortedJoinCustomStrFuncSlice(asSlice, func(c connMapEntry) string { return c.fullExplanationString() }, common.ShortSep)
}

func (c connMapEntry) fullExplanationString() string {
	header := fmt.Sprintf("src: %s, dst: %s", c.Src.Name(), c.Dst.Name())
	deniedConn := netset.AllTransports().Subtract(c.Conn.Conn)
	allowedConns := fmt.Sprintf("allowed connections: %s, rules details:\n%s", c.Conn.Conn.String(), c.Conn.DetailedExplanationString(c.Conn.Conn))
	deniedConns := fmt.Sprintf("denied connections: %s, rules details:\n%s", deniedConn.String(), c.Conn.DetailedExplanationString(deniedConn))
	return strings.Join([]string{header, allowedConns, deniedConns}, "\n")
}
