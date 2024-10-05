package dfw

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/model/endpoints"
)

// https://dp-downloads.broadcom.com/api-content/apis/API_NTDCRA_001/4.2/html/api_includes/types_SecurityPolicy.html

type dfwCategory int

const (
	ethernetCategory dfwCategory = iota
	emergencyCategory
	infrastructureCategory
	envCategory
	appCategoty
	emptyCategory
)

const (
	EthernetStr       = "Ethernet"
	EmergencyStr      = "Emergency"
	InfrastructureStr = "Infrastructure"
	EnvironmentStr    = "Environment"
	ApplicationStr    = "Application"
	EmptyStr          = "<Empty>"
)

func dfwCategoryFromString(s string) dfwCategory {
	switch s {
	case EthernetStr:
		return ethernetCategory
	case EmergencyStr:
		return emergencyCategory
	case InfrastructureStr:
		return infrastructureCategory
	case EnvironmentStr:
		return envCategory
	case ApplicationStr:
		return appCategoty
	case EmptyStr:
		return emptyCategory
	default:
		return emptyCategory
	}

}

func (d dfwCategory) string() string {
	switch d {
	case ethernetCategory:
		return EthernetStr
	case emergencyCategory:
		return EmergencyStr
	case infrastructureCategory:
		return InfrastructureStr
	case envCategory:
		return EnvironmentStr
	case appCategoty:
		return ApplicationStr
	case emptyCategory:
		return EmptyStr
	default:
		return ""
	}
}

var categoriesList = []dfwCategory{
	ethernetCategory, emergencyCategory, infrastructureCategory, envCategory, appCategoty, emptyCategory,
}

type categorySpec struct {
	category      dfwCategory
	rules         []*fwRule // ordered list of rules
	defaultAction ruleAction
}

// allowedConns are the set of connections between src to dst, for which this category allows the connection
// jumpToAppConns are the set of connections between src to dst, for which this category applies the rule action jump_to_app
// notDeterminedConns are the set of connections between src to dst, for which this category has no verdict (no relevant rule + no default defined),
// thus are expected to be inspected by the next cateorgy (or by the "global default") if this is the last category
// todo: may possibly eliminate jumpToAppConns and unify them with notDeterminedConns
func (c *categorySpec) analyzeCategory(src, dst *endpoints.VM, isIngress bool) (allowedConns, jumpToAppConns, deniedConns, notDeterminedConns *connection.Set) {
	allowedConns, jumpToAppConns, deniedConns = connection.None(), connection.None(), connection.None()
	for _, rule := range c.rules {
		if rule.capturesPair(src, dst, isIngress) {
			switch rule.action {
			case actionAllow:
				addedAllowedConns := rule.conn.Subtract(deniedConns).Subtract(jumpToAppConns)
				allowedConns = allowedConns.Union(addedAllowedConns)
			case actionDeny:
				addedDeniedConns := rule.conn.Subtract(allowedConns).Subtract(jumpToAppConns)
				deniedConns = deniedConns.Union(addedDeniedConns)
			case actionJumpToApp:
				addedJumpToAppConns := rule.conn.Subtract(allowedConns).Subtract(deniedConns)
				jumpToAppConns = jumpToAppConns.Union(addedJumpToAppConns)
			}
		}
	}
	switch c.defaultAction {
	case actionNone: // no default configured for this category
		return allowedConns, jumpToAppConns, deniedConns, connection.All().Subtract(allowedConns).Subtract(deniedConns).Subtract(jumpToAppConns)
	case actionAllow: // default allow
		return connection.All().Subtract(deniedConns).Subtract(jumpToAppConns), jumpToAppConns, deniedConns, connection.None()
	case actionDeny: // default deny
		return allowedConns, jumpToAppConns, connection.All().Subtract(allowedConns).Subtract(jumpToAppConns), connection.None()
	default:
		return nil, nil, nil, nil // invalid default action (todo: add err? )
	}
}

func (c *categorySpec) string() string {
	rulesStr := make([]string, len(c.rules)+1)
	rulesStr[0] = "rules:"
	for i := range c.rules {
		rulesStr[i+1] = c.rules[i].string()
	}
	return fmt.Sprintf("category: %s\n%s\ndefault action: %s", c.category.string(), strings.Join(rulesStr, lineSeparatorStr), string(c.defaultAction))

}

func (c *categorySpec) addRule(src, dst []*endpoints.VM, conn *connection.Set, action string, direction string, origRule *collector.Rule) {
	newRule := &fwRule{
		srcVMs:      src,
		dstVMs:      dst,
		conn:        conn,
		action:      actionFromString(action),
		direction:   direction,
		origRuleObj: origRule,
	}
	c.rules = append(c.rules, newRule)
}

func newEmptyCategory(c dfwCategory) *categorySpec {
	return &categorySpec{
		category:      c,
		defaultAction: actionNone,
	}
}
