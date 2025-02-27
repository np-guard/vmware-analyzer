# Synthesize k8s network policy resources from NSX DFW config

Synthesize a given NSX DFW configuration into an equivalent k8s network policy. 

```
Flags:
  -- synthesis-dump-dir         flag to run synthesis; specify directory path to store k8s synthesis results
  -- synth                      flag to run synthesis, even if synthesis-dump-dir is not specified
  -- synth-create-dns-policy    flag to create a policy allowing access to target env dns pod
  -- synthesize-admin-policies  flag to synthesize category environment into admin network policies (which included deny, pass and priority) (default false)
  -- disjoint-hint              comma separated list of NSX groups/tags that are always disjoint in their VM members, 
  needed for an effective and sound synthesis process, can specify more than one hint 
  (example: --disjoint-hint frontend,backend --disjoint-hint app,web,db) 
```

## Overview
Synthesize a given `NSX DFW` policy into k8s network policy.
The result may not be totally equivalent, due to limitations of the target policy; more details regarding the k8s synthesis [here](#limitation).
There are two main challenges here: 
* *The flattening challenge*: translating prioritized set of rules with actions `allow/deny/jump-to-app` into a flat set of  `allow` rules (which is what k8s network policies support).
* *The intent preserving challenge*: maintain the original semantic intent of the rules
and not just generate a set of rules that preserves the connectivity between VMs given the current state of the configuration.


### The flattening challenge
There are two modes of policies synthesis, depending on the value of `synthesize-admin-policies`; when
it is not active then priortized `allow, deny, jump-to-app` rules from all `NSX categories` should be synthesized to 
`k8s network policy`, namely, to `flat allow rules`; when it is activated then rules from `NSX category environment` should be synthesized to  
`admin network policy` which rules have `allow, deny, pass` and priority; other categories should be synthesized as
before to `k8s network policy`. 

For example, for [this example](pkg/data/exampleHogwarts.go) there are two related files: 
[no admin policies](pkg/synthesis/tests_expected_output/abstract_models/ExampleHogwarts.txt), which is the result of execution
without `-- synthesize-admin-policies` and contains translation of all rules to flat allow rules; and 
[with admin policies](pkg/synthesis/tests_expected_output/abstract_models/ExampleHogwartsAdmin_AdminPoliciesEnabled.txt),
result of execution with `-- synthesize-admin-policies`, contains the translation when `NSX category env` 
is synthesized to admin polices that can use `deny/pass/allow` and priorities. Full synthesis results for this example can be found 
[here](pkg/synthesis/tests_expected_output/k8s_resources/ExampleHogwarts)
for non-admin polices and [here](pkg/synthesis/tests_expected_output/k8s_resources/ExampleHogwartsAdmin_AdminPoliciesEnabled) 
for admin policies.

The translation of priortized `allow,deny,jump-to-app` rules into flat `allow` rules is exponential in the size of the
original rules (to be accurate, the number of allow rules generated for each original allow rule is
exponential in the number of term in this allow rule and in higher priority deny and pass rules). To tackle this we:
1. Ask the user to provide the tool with `hints` -  lists of disjoint tags/groups.
E.g., tags `{frontend, backend}` are disjoint.
In the future it is planned to "guess" these disjoint sets, and ask the user to approve them. E.g., 
for [this example](pkg/data/exampleHint.go) there are two related files: [flat allow rules without hints](pkg/synthesis/tests_expected_output/abstract_models/ExampleHintsDisjoint_NoHint_NoHint.txt)
contains the flat allow rules when executed without hints; and [flat allow rules with hints](pkg/synthesis/tests_expected_output/abstract_models/ExampleHintsDisjoint.txt) 
contains the flat allow when executed with `--disjoint-hint sly, huf, gry, dum1, dum2` 
2. Apply various optimization to simplify the resulting rules and to delete redundant rules; the more accurate hints the
tool is provided, the more concise and readable rules it will synthesize.  

### The policy preserving challenge
The synthesis maintains the original semantic intent of the rules
and not just generates a set of rules that preserves the connectivity between VMs given the current state of the configuration.
For example:
* When a `frontend` `VM` is added it should be granted the policies defined for the `frontend`
* A DFW rule that uses an NSX group with no VMs at the moment of analysis and synthesis,
will still be relevant to maintain in the conversion to network policies.

To preserve the original intent of the policy, the synthesized policy prioritizes referencing non-ephemeral features.
E.g., it prefers referencing`frontend` label instead of referencing `VMs'` names. `VM`s may be deleted and added, while
the `frontend` label is always granted to any relevant `VM`.  
Specifically,  given a rule with `src`defined as group `aaa` which is defined as `tag = backend and tag != DB`,
the synthesized policy will reference the labels corresponding to the `backend` and `DB`  values.

`todo: add tag -> labeling machanism` 

## Currently supported
Currently, the tool supports groups defined by expressions over tags; `nested NSX expression` are not yet supported.
If a group is defined by an expression that we do not yet support, then the synthesized policy will refer just to the group, 
and the relevant *VM*s will be granted labels of this group.

For example, the expression `tag = backend and tag != DB` is supported, while the nested expression
`(tag = backend and tag != DB) or (tag = research) ` is not supported. For a group defined over the former expression,
the synthesis will reference labels corresponding to the above tags' values, while for a group defined over the latter 
expression, the synthesis will reference a label corresponding to the group.

## Output
### Synthesized k8s resource
`k8s_resources` folder under the folder specified in `synthesis-dump-dir` contains the following files:
* **pods.yaml** the list pods (as placeholder for VMs resources for now) with the relevant labels of each pod.
The labels are added based on original VMs' tags and groups in NSX env. 
* **policies.yaml** the k8s policies

The combination of the policies and the pods' labels:
1. Satisfies the snapshot of the connectivity at the time of the synthesis
2. Preserve the policy's intent, as expressed e.g. by *tags*, for future changes 
(e.g. adding a `VM` or changing its functionality and thus its labeling)


<a id="limitation"></a>
#### limitations
There are differences in the expression power between `NSX DFW` to `Kubernetes Network Policies`; e.g. `ICMP protocols`
support depends on the network plugin and is not supported by our synthesis. 

## Debugging
The synthesize process is a complex one. Along it, in order to have the intent preserving synthesis as explained above,
we use a *symbolic* representation of the *rules*: each *symbolic rule* is a `priority`, an `action`, a
`src`, a `dst` and a `connection`; The priority in a natural number; the action is `allow/deny/pass`; The `src` and the `dst` are `Conjunctions` of simple expressions 
(equal/not equal) over e.g. `tags`;  the `connection` is a protocol and potentially `src/dst` min and max ports.

The synthesis dump directory (specified in `synthesis-dump-dir`) contains (among others) the following files:
* under subdirectory **debug_dir**
  * **config.txt** Contains the NSX config as being read by the tool; this includes `VMs`, `groups` and `firewall rules`.
  * **pre_processing.txt** Contains the translation of the firewall rule into `symbolic rules` ; e.g., if a specific 
src is a group which is an expression over tags, then this file will have this rule's `src` defined over tags.
  * **abstract_model.txt** The tool translates the *allow/deny/pass* rules from `pre_processing.txt` into an abstract model that
    contains the rules to be syntactically translated to `k8s policies`. If `synthesize-admin-policies`  is off then all rules must
    be `flat allow rules`, and so all the rules in the abstract model are non-prioritized with action `allow`;
    otherwise rules originating from the `environment` category are translated to admin policies with
    a priority and an allow/deny/pass action; rules that originate from the other categories are flat allow rules.
  `abstract_model.txt` contains these rules and a list of the groups, each groups with the expression that defined
  it and the snapshot of the *VMs* in the group. 

 The following log files contain warning messages and various debug printing of the different stages
 of the synthesis, as following:

  * **runPreprocessing.log** Log of the stage in which the NSX rules are translated to symbolic rules.
  * **runConvertToAbstract.log** Log of the stage in which the symbolic rules from the preprocessing stage 
are translated to the abstract model's rules.  
  * **runK8SSynthesis.log** Log of the stage in which the k8s yaml pods and polices files are synthesized from 
the abstract model.
