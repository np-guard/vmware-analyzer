package dfw

/*type relevantRules struct {
	egressAllow  []*FwRule
	egressDeny   []*FwRule
	ingressAllow []*FwRule
	ingressDeny  []*FwRule
}*/

/*func calcExplanation(allowEgress, allowIngress *netset.TransportSet, relevantRules *relevantRules) *conns.Explanation {
	res := &conns.Explanation{}

	// connections that are denied by an egress rule:
	denyEgress := netset.AllTransports().Subtract(allowEgress)
	deniedConnsByEgress := splitConnByRulesConn(denyEgress, relevantRules.egressDeny)
	for _, denyRuleAndConn := range deniedConnsByEgress {
		res.AddExplanation(denyRuleAndConn.Conn, denyRuleAndConn.Rule, 0, false)
	}

	// connections that are allowed by an egress rule:
	allowConnsByEgress := splitConnByRulesConn(allowEgress, relevantRules.egressAllow)
	for _, egressAllowRuleAndConn := range allowConnsByEgress {
		// connections that are allowed by an egress rule, but denied by an ingress rule:
		denyIngress := egressAllowRuleAndConn.Conn.Subtract(allowIngress)
		deniedConnsByIngress := splitConnByRulesConn(denyIngress, relevantRules.ingressDeny)
		for _, ingressDenyRuleAndConn := range deniedConnsByIngress {
			res.AddExplanation(ingressDenyRuleAndConn.Conn, egressAllowRuleAndConn.Rule, ingressDenyRuleAndConn.Rule, false)
		}
		// connections that are allowed by an egress rule, and by an ingress rule:
		allowConnsByIngress := splitConnByRulesConn(egressAllowRuleAndConn.Conn, relevantRules.ingressAllow)
		for _, ingressAllowRuleAndConn := range allowConnsByIngress {
			res.AddExplanation(ingressAllowRuleAndConn.Conn, egressAllowRuleAndConn.Rule, ingressAllowRuleAndConn.Rule, true)
		}
	}
	return res
}*/

// splitConnByRulesConn() split the connectivity according to the rules connectivity
/*func splitConnByRulesConn(conn *netset.TransportSet, rules []*FwRule) []conns.RuleAndConn {
	res := []conns.RuleAndConn{}
	for _, rule := range rules {
		relevantConn := rule.conn.Intersect(conn)
		if !relevantConn.IsEmpty() {
			res = append(res, conns.RuleAndConn{Conn: relevantConn, Rule: rule.ruleID})
			// the subtract below, makes sure that only connections not included in higher-prio rules are considered for next rules.
			conn = conn.Subtract(relevantConn)
		}
	}
	// todo - what to do if conn is not empty at the end?
	return res
}
*/
