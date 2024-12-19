package dfw

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/model/conns"
)

type relevantRules struct {
	egressAllow  []*FwRule
	egressDeny   []*FwRule
	ingressAllow []*FwRule
	ingressDeny  []*FwRule
}

func calcExplanation(allowEgress, allowIngress *netset.TransportSet, relevantRules *relevantRules) *conns.Explanation {
	res := &conns.Explanation{}

	// connections that are denied by an egress rule:
	denyEgress := netset.AllTransports().Subtract(allowEgress)
	deniedConnsByEgress := splitConnByRulesConn(denyEgress, relevantRules.egressDeny)
	for _, denyRuleAndConn := range deniedConnsByEgress {
		res.AddExplanation(denyRuleAndConn.conn, denyRuleAndConn.rule, 0, false)
	}

	// connections that are allowed by an egress rule:
	allowConnsByEgress := splitConnByRulesConn(allowEgress, relevantRules.egressAllow)
	for _, egressAllowRuleAndConn := range allowConnsByEgress {
		// connections that are allowed by an egress rule, but denied by an ingress rule:
		denyIngress := egressAllowRuleAndConn.conn.Subtract(allowIngress)
		deniedConnsByIngress := splitConnByRulesConn(denyIngress, relevantRules.ingressDeny)
		for _, ingressDenyRuleAndConn := range deniedConnsByIngress {
			res.AddExplanation(ingressDenyRuleAndConn.conn, egressAllowRuleAndConn.rule, ingressDenyRuleAndConn.rule, false)
		}
		// connections that are allowed by an egress rule, and by an ingress rule:
		allowConnsByIngress := splitConnByRulesConn(egressAllowRuleAndConn.conn, relevantRules.ingressAllow)
		for _, ingressAllowRuleAndConn := range allowConnsByIngress {
			res.AddExplanation(ingressAllowRuleAndConn.conn, egressAllowRuleAndConn.rule, ingressAllowRuleAndConn.rule, true)
		}
	}
	return res
}

type ruleAndConn struct {
	conn *netset.TransportSet
	rule int
}

// splitConnByRulesConn() split the connectivity according to the rules connectivity
func splitConnByRulesConn(conn *netset.TransportSet, rules []*FwRule) []ruleAndConn {
	res := []ruleAndConn{}
	for _, rule := range rules {
		relevantConn := rule.conn.Intersect(conn)
		if !relevantConn.IsEmpty() {
			res = append(res, ruleAndConn{relevantConn, rule.ruleID})
			conn = conn.Subtract(relevantConn)
		}
	}
	// todo - what to do if conn is not empty at the end?
	return res
}
