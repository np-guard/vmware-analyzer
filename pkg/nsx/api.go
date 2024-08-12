package nsx

/*
initial plan:
- model DFW (with initially supported fields) (and default rules)
- model Sections env, app
- implement basic analysis to produce connectivity map/ required connectivity
- demonstrate synthesis based on this analysis result
*/

// intenal modeling for nsx DFW

/*
input example - dfw rules
 "MGMT" =>   "ip_addresses": [
                    "192.168.100.1/32",
                    "192.168.110.10/32"
                  ],


groups:
https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_vm_tags
https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_group
 For Tag criteria, use 'scope|value' notation if you wish to specify scope in criteria

  "display_name": "WEBAPP",
              "expression": [
                {
                  "member_type": "VirtualMachine",
                  "key": "Tag",
                  "operator": "EQUALS",
                  "value": "webapp|",
                  "resource_type": "Condition",
                  "marked_for_delete": "false"

 "display_name": "LB",
              "expression": [
                {
                  "member_type": "VirtualMachine",
                  "key": "Tag",
                  "operator": "EQUALS",
                  "value": "webapp|lb",
                  "resource_type": "Condition",
                  "marked_for_delete": false

    "display_name": "WEB",
              "expression": [
                {
                  "member_type": "VirtualMachine",
                  "key": "Tag",
                  "operator": "EQUALS",
                  "value": "webapp|web",
                  "resource_type": "Condition",
                  "marked_for_delete": false
                }

              "display_name": "APP",
              "expression": [
                {
                  "member_type": "VirtualMachine",
                  "key": "Tag",
                  "operator": "EQUALS",
                  "value": "webapp|app",
                  "resource_type": "Condition",
                  "marked_for_delete": false

             "id": "DB",
              "display_name": "DB",
              "expression": [
                {
                  "member_type": "VirtualMachine",
                  "key": "Tag",
                  "operator": "EQUALS",
                  "value": "webapp|db",


- name: "webapp" ,  description: "webapp Policy",
rules:
	- "id": "webapp-rule-01", "description": "webapp-rule-01", "display_name": "Management Outbound", "sequence_number": 50,"source_groups": [ "ANY"], "destination_groups": ["/infra/domains/default/groups/MGMT"],"services": ["ANY"],"action": "ALLOW", "scope": ["/infra/domains/default/groups/WEBAPP"]
	- "id": "webapp-rule-02", "description": "webapp-rule-02", "display_name": "Management Inbound", "sequence_number": 60, "source_groups":  ["/infra/domains/default/groups/MGMT"],  "destination_groups":  [ "ANY"], "services": ["ANY"],"action": "ALLOW", "scope": ["/infra/domains/default/groups/WEBAPP"]
	- "id": "webapp-rule-03", "description": "webapp-rule-03", "display_name": "LB to WEB",  "sequence_number": 70, "source_groups": ["/infra/domains/default/groups/LB"], "destination_groups": ["/infra/domains/default/groups/WEB"], "services": ["/infra/services/HTTPS"], action": "ALLOW", "scope": ["/infra/domains/default/groups/WEBAPP"]
	- "id": "webapp-rule-04", "description": "webapp-rule-04", "display_name": "WEB to APP", "sequence_number": 80, "source_groups": ["/infra/domains/default/groups/WEB"],  "destination_groups": ["/infra/domains/default/groups/APP"],  "services": ["/infra/services/tcp_8443"], "action": "ALLOW", "scope": ["/infra/domains/default/groups/WEBAPP"]
	- "id": "webapp-rule-05", "description": "webapp-rule-05", "display_name": "APP to DB", "sequence_number": 90, "source_groups": ["/infra/domains/default/groups/APP"], "destination_groups": ["/infra/domains/default/groups/DB"], "services": ["/infra/services/HTTP"], action": "ALLOW", "scope": ["/infra/domains/default/groups/WEBAPP"]
	- "id": "webapp-rule-06", "description": "webapp-rule-06", "display_name": "Block the rest", "sequence_number": 100, "source_groups": [ "ANY"], "destination_groups": ["/infra/domains/default/groups/MGMT"],"services": ["ANY"],"action": "DROP", "scope": ["/infra/domains/default/groups/WEBAPP"]


*/

/*
 rules fields docs: (https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_security_policy_rule )


 sequence_number - (Required) This field is used to resolve conflicts between multiple Rules under Security or Gateway Policy for a Domain. Please note that sequence numbers should start with 1 and not 0 to avoid confusion.

 action - (Optional) Rule action, one of ALLOW, DROP, REJECT and JUMP_TO_APPLICATION. Default is ALLOW. JUMP_TO_APPLICATION is only applicable in Environment category.

 source_groups - (Optional) Set of group paths that serve as the source for this rule. IPs, IP ranges, or CIDRs may also be used starting in NSX-T 3.0. An empty set can be used to specify "Any".

 sources_excluded - (Optional) A boolean value indicating negation of source groups.

 direction - (Optional) Traffic direction, one of IN, OUT or IN_OUT. Default is IN_OUT.

 tag - (Optional) A list of scope + tag pairs to associate with this policy.

 policy_path - (Required) The path of the Security Policy which the object belongs to

 scope - (Optional) Set of policy object paths where the rule is applied.

 services - (Optional) Set of service paths to match.



 security_policy fields:

 category - (Required) Category of this policy. For local manager must be one of Ethernet, Emergency, Infrastructure, Environment, Application. For global manager must be one of: Infrastructure, Environment, Application.
 scope - (Optional) The list of policy object paths where the rules in this policy will get applied.
 stateful - (Optional) If true, state of the network connects are tracked and a stateful packet inspection is performed. Default is true.
 tcp_strict - (Optional) Ensures that a 3 way TCP handshake is done before the data packets are sent. Default is false.
*/

/*
 "member_type": "VirtualMachine",
                  "key": "Tag",
                  "operator": "EQUALS",
                  "value": "webapp|db",
                  "resource_type": "Condition",



type NsGroupTagExpression struct {
	ResourceType string `json:"resource_type"`

	// The tag.scope attribute of the object
	Scope string `json:"scope,omitempty"`

	// Operator of the scope expression eg- tag.scope = \"S1\".
	ScopeOp string `json:"scope_op,omitempty"`

	// The tag.tag attribute of the object
	Tag string `json:"tag,omitempty"`

	// Operator of the tag expression eg- tag.tag = \"Production\"
	TagOp string `json:"tag_op,omitempty"`

	// Type of the resource on which this expression is evaluated
	TargetType string `json:"target_type"`
}


https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_security_policy
action - (Optional) Rule action, one of ALLOW, DROP, REJECT and JUMP_TO_APPLICATION. Default is ALLOW. JUMP_TO_APPLICATION is only applicable in Environment category
*/
