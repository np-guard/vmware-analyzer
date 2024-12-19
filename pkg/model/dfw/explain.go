package dfw

import (
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/pkg/model/conn"
)

type relevantRules struct {
	egressAllow  []*FwRule
	egressDeny   []*FwRule
	ingressAllow []*FwRule
	ingressDeny  []*FwRule
}

func calcExplanation(egress, ingress *netset.TransportSet, relevantRules *relevantRules) *conn.Explanation {
	res := &conn.Explanation{}
	denyEgress := netset.AllTransports().Subtract(egress)
	deniedConnsByEgress := splitByRules(denyEgress, relevantRules.egressDeny)
	for _, denyRuleAndConn := range deniedConnsByEgress {
		res.AddExplanation(denyRuleAndConn.conn, denyRuleAndConn.rule, 0, false)
	}
	allowConnsByEgress := splitByRules(egress, relevantRules.egressAllow)
	for _, egressAllowRuleAndConn := range allowConnsByEgress {
		denyIngress := egressAllowRuleAndConn.conn.Subtract(ingress)
		deniedConnsByIngress := splitByRules(denyIngress, relevantRules.ingressDeny)
		for _, ingressDenyRuleAndConn := range deniedConnsByIngress {
			res.AddExplanation(ingressDenyRuleAndConn.conn, egressAllowRuleAndConn.rule, ingressDenyRuleAndConn.rule, false)
		}
		allowConnsByIngress := splitByRules(egressAllowRuleAndConn.conn, relevantRules.ingressAllow)
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

func splitByRules(conn *netset.TransportSet, rules []*FwRule) []ruleAndConn {
	res := []ruleAndConn{}
	for _, rule := range rules {
		relevantConn := rule.conn.Intersect(conn)
		if !relevantConn.IsEmpty() {
			res = append(res, ruleAndConn{relevantConn, rule.ruleID})
			conn = conn.Subtract(relevantConn)
		}
	}
	return res
}
