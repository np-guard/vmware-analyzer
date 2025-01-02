// todo: rename package
package conns

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// ConnMap captures permitted connections between endpoints in the input config
type ConnMap map[*endpoints.VM]map[*endpoints.VM]*DetailedConnection

// connMapEntry captures one entry in ConnMap
type connMapEntry struct {
	Src, Dst *endpoints.VM
	Conn     *DetailedConnection
}

/*func (c connMapEntry) String() string {
	return fmt.Sprintf("src:%s, dst: %s, allowedConns: %s ", c.Src.Name(), c.Dst.Name(), c.Conn.String())
}*/

func (c connMapEntry) FullExplanationString() string {
	header := fmt.Sprintf("src: %s, dst: %s", c.Src.Name(), c.Dst.Name())
	deniedConn := netset.AllTransports().Subtract(c.Conn.Conn)
	allowedConns := fmt.Sprintf("allowed connections: %s, rules details:\n%s", c.Conn.Conn.String(), c.Conn.DetailedExplanationString(c.Conn.Conn))
	deniedConns := fmt.Sprintf("denied connections: %s, rules details:\n%s", deniedConn.String(), c.Conn.DetailedExplanationString(deniedConn))
	return strings.Join([]string{header, allowedConns, deniedConns}, "\n")
}

func (c ConnMap) GetExplanationPerConnection(srcVM, dstVM string, inputConn *netset.TransportSet) (isAllowed bool, ingress []int, egress []int) {
	logging.Debugf("GetExplanationPerConnection")
	for src, srcMap := range c {
		if src.Name() != srcVM {
			//logging.Debugf("src.Name: %s, srcVM: %s", src.Name(), srcVM)
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

// add func adds a given pair with specified permitted connection
func (c ConnMap) Add(src, dst *endpoints.VM, conn *DetailedConnection) {
	if _, ok := c[src]; !ok {
		c[src] = map[*endpoints.VM]*DetailedConnection{}
	}
	c[src][dst] = conn
}

// initPairs adds all possible pairs with allow-all or deny-all, based on initAllow
func (c ConnMap) InitPairs(initAllow bool, vms []*endpoints.VM, vmsFilter []string) {
	vmsToaAnalyze := map[string]bool{}
	if len(vmsFilter) > 0 {
		for _, vmName := range vmsFilter {
			vmsToaAnalyze[vmName] = true
		}
	}
	for _, src := range vms {
		for _, dst := range vms {
			if src == dst {
				continue
			}
			if len(vmsFilter) > 0 && !(vmsToaAnalyze[src.Name()] && vmsToaAnalyze[dst.Name()]) {
				continue
			}
			if initAllow {
				c.Add(src, dst, NewAllDetailedConnection())
			} else {
				c.Add(src, dst, NewEmptyDetailedConnection())
			}
		}

	}
}

// String returns a concatenated lines strings with all VM pairs and their permitted connections.
// If the input vms list is not empty, if returns only connection lines with pairs contained in this list.
// Todo: sunset this:
func (c ConnMap) String() string {
	return c.FullOutputWithExplanations()
	//asSlice := c.ToSlice()
	//return common.SortedJoinStringifiedSlice(asSlice, "\n")

	/*lines := make([]string, len(asSlice))
	for i, e := range asSlice {
		lines[i] = fmt.Sprintf("src:%s, dst: %s, allowedConns: %s ", e.Src.Name(), e.Dst.Name(), e.Conn.String())
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")*/
}

func (c ConnMap) FullOutputWithExplanations() string {
	asSlice := c.ToSlice()
	return common.SortedJoinCustomStrFuncSlice(asSlice, func(c connMapEntry) string { return c.FullExplanationString() }, common.ShortSep)
}

func (c ConnMap) Filter(vms []string) ConnMap {
	if len(vms) == 0 {
		return c
	}
	newC := ConnMap{}
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			if slices.Contains(vms, src.Name()) && slices.Contains(vms, dst.Name()) {
				newC.Add(src, dst, conn)
			}
		}
	}
	return newC
}

func (c ConnMap) ToSlice() (res []connMapEntry) {
	for src, srcMap := range c {
		for dst, conn := range srcMap {
			res = append(res, connMapEntry{src, dst, conn})
		}
	}
	return res
}
