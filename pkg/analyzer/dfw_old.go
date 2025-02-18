package model

// category: start with  Environment & Application
/*
Categories are evaluated from left to right (Ethernet > Emergency > Infrastructure > Environment > Application),
and the distributed firewall rules within the category are evaluated top down.
// todo: consider also Ethernet, Emergency, Infrastructure
// (see
https://docs.vmware.com/en/VMware-NSX/4.2/administration/GUID-6AB240DB-949C-4E95-A9A7-4AC6EF5E3036.html#GUID-6AB240DB-949C-4E95-A9A7-4AC6EF5E3036
https://docs.vmware.com/en/VMware-NSX/4.2/administration/GUID-6AB240DB-949C-4E95-A9A7-4AC6EF5E3036.html#GUID-6AB240DB-949C-4E95-A9A7-4AC6EF5E3036
)


There is a pre-determined order in which the policy framework manages the
priority of these security policies. Ethernet category is for supporting layer 2
firewall rules. The other four categories are applicable for layer 3 rules.
Amongst them, the Emergency category has the highest priority followed by
Infrastructure, Environment and then Application rules
Administrator can choose to categorize a security policy into the above categories or can
choose to leave it empty. If empty it will have the least precedence w.r.t the above
four categories.


Questions:
- if a packet reaches a default allow action per categoty, does it proceed to be evaluated on the next category?

- see clarification about jump-to-app action:
This action is only available for the Environment category.
Allows the traffic that matches with Environment category rules to continue on for the Application category rules to apply.
Use this action when traffic matches with Environment category rules and exits, but you want the Application category rules to apply.
For example, if there is an Environment category rule with the action Allow for a specific source and there is an Application category
rule with the action Drop for the same source, packets that match the Environment category are allowed through the firewall and further rules are no longer applied.
With the Jump to Application action, the packets matches the Environment category rule, but continues on to the Application category rules
and the result is that those packets are dropped.


- evaluation of rules:
Distributed Firewall Rule processing:

    Rules are processed in top-to-bottom fashion. This means topmost rule is evaluated first.
    First matching DFW rule from the top is applied on the vnic.
    Search then ends and no other rules are checked.

The default rule on NSX Distributed Firewall will be enforced if packets do not match any user defined DFW rule in any of the categories.

It is a best practice to change the default rule to ‘drop’ action after configuring all the required DFW rules for the applications.


Updates about default rule:
each category can be configured with or without a default rule.

Connectivity preference Enum: ALLOWLIST, DENYLIST, ALLOWLIST_ENABLE_LOGGING, DENYLIST_ENABLE_LOGGING, NONE

Based on the connectivity preference, a default rule for this
security policy will be created. An appropriate action will be set on
the rule based on the value of the connectivity preference. If NONE is
selected or no connectivity preference is specified, then no default
rule for the security policy gets created. The default rule that gets
created will be a any-any rule and applied to entities specified in the
scope of the security policy. Specifying the connectivity_preference
without specifying the scope is not allowed. The scope has to be a
Group and one cannot specify IPAddress directly in the group that is
used as scope. This default rule is only applicable for the Layer3
security policies.
ALLOWLIST - Adds a default drop rule. Administrator can then use "allow"
rules to allow traffic between groups
DENYLIST - Adds a default allow rule. Admin can then use "drop" rules
to block traffic between groups
ALLOWLIST_ENABLE_LOGGING - Allowlisting with logging enabled
DENYLIST_ENABLE_LOGGING - Denylisting with logging enabled
NONE - No default rule is created.

Q: what if there is no default for any category? what is the "global" default?
(maybe there is a default security policy for the DFW)

*/

/*
type ruleAction string

type dfwCategory int

const (
	ethernetCategory dfwCategory = iota
	emergencyCategory
	infrastructureCategory
	envCategory
	appCategoty
	emptyCategory
)

type categorySpec struct {
	category      dfwCategory
	rules         []*fwRule // ordered list of rules
	defaultAction ruleAction
}

type dfw struct {
	categoriesSpecs []*categorySpec // ordered list of categories
	defaultAction   ruleAction      // global default (?)
}

func (c *categorySpec) analyzeCategory(src, dst *vm) (allowedConns, jumpToAppConns *connection.Set) {
	var deniedConns *connection.Set
	allowedConns, jumpToAppConns, deniedConns = connection.None(), connection.None(), connection.None()
	for _, rule := range c.rules {
		if rule.capturesPair(src, dst) {
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
	if c.defaultAction == actionAllow { // default allow
		return connection.All().Subtract(deniedConns).Subtract(jumpToAppConns), jumpToAppConns
	}
	// else - default deny
	return allowedConns, jumpToAppConns
}

// for a pair of src,dst vms, return the set of allowed connections
func (d *dfw) analyzeDFW(src, dst *vm) *connection.Set {
	allAllowedConns := connection.None()
	for _, dfwCategory := range d.categoriesSpecs {
		if dfwCategory.category < envCategory {
			continue // currently support only env and app categories
		}
		allowedConns, jumpToAppConns := dfwCategory.analyzeCategory(src, dst)
		allAllowedConns = allAllowedConns.Union(allowedConns)
	}

}
*/
