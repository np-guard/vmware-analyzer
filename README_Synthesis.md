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
  (example: \"--" + disjointHintsFlag + " frontend,backend --" + disjointHintsFlag + " app,web,db\") 
```

## Overview
Synthesize a given NSX DFW policy into k8s network policy.
There are two main challenges here: 
* *The flattening challenge*: translating prioritized set of rules with actions `allow/deny/jump-to-app` into a flat set of  `allow` rules (which is what k8s network policies support).
* *The intent preserving challenge*: maintain the original semantic intent of the rules, and not just synthesis a snapshot. 
This is important since e.g. once a new VM is added with the relevant tags/labels in the target env, it will be granted the desired connectivity.

### The flattening challenge
The translation of priortized `allow,deny,jump-to-app` rules into flat `allow` rules is exponential in the number of terms of the
original rules (to be accurate, the number of allow rules generated for each original allow rule is
exponential in the number of term in this allow rule and in higher priority deny and pass rules). To tackle this we:
1. Ask the user to provide the tool with _hints_ -  lists of disjoint tags/groups.
E.g., tags _{frontend, backend}_ are disjoint.
In the future it is planned to "guess" these
disjoint sets, and ask the user to approve them.
2. Apply various optimization to simplify the resulting rules and to delete redundant rules; the more accurate hints the
tool is provided, the more concise and readable rules it will synthesize.  

### The policy preserving challenge
To preserve the original intent of the policy, the synthesized policy refers, where possible, to permanent labeling such
as tags - e.g. _front-end_ - and not to temporarily labeling such as _VM_ names. E.g., a specific rule's _src_ is
 defined to be group _aaa_ that is defined as _tag = backend_ and _tag != DB_ then the synthesized policy will refer to the value
of the tag.

## Currently supported
Currently, the tool supports groups defined by expressions over tags; nested expression are not yet supported.
If a group is defined 
by an expression that we do not yet support, then the synthesized policy will refer just to the group, and the 
relevant *VM*s will be granted labels of this group. In the following releases we will expend our expressions support. 

## Output
_k8s_resources_ dir under the dir specified in _synthesis-dump-dir_ contains the following files:
* **pods.yaml** the list pods (as place holder for VMs resources for now) with the relevant labels of each pod.
The labels are added based on original VMs' tags and groups in NSX env. 
* **policies.yaml** the k8s policies

The combination of the policies and the pods' labels:
1. Satisfies the snapshot of the connectivity at the time of the synthesis
2. Preserve the policy's intent, as expressed e.g. by *tags*, for future changes 
(e.g. adding a _VM_ or changing its functionality and thus its labeling)

## Debugging
The synthesize process is a complex one. Along it, in order to have the intent preserving synthesis as explained above,
we use a *symbolic* representation of the *rules*: each *symbolic rule* is a _priority_, an _action_, a
_src_, a _dst_ and a _connection_; The priority in a natural number; the action is _allow/deny/pass_; The _src_ and the _dst_ are _Conjunctions_ of simple expressions 
(equal/not equal) over e.g. _tags_;  the _connection_ is a protocol and potentially _src/dst_ min and max ports.

The synthesis dump directory (specified in _synthesis-dump-dir_) contains (among others) the following files:
* under subdirectory **debug_dir**
  * **config.txt** Contains the NSX config as being read by the tool; this includes _VMs_, _groups_ and _firewall rules_.
  * **pre_processing.txt** Contains the translation of the firewall rule into _symbolic rules_ ; e.g., if a specific 
src is a group which is an expression over tags, then this file will have this rule's _src_ defined over tags.
  * **abstract_model.txt** The tool translates the *allow/deny/pass* rules from _pre_processing.txt_ into an abstract model that
    contains the rules to be syntactically translated to _k8s policies_. If _synthesize-admin-policies_  is off then all rules must
    be _flat allow rules_, and so all the rules in the abstract model are non-prioritized with action _allow_;
    otherwise rules originating from the _environment_ category are translated to admin policies with
    a priority and an allow/deny/pass action; rules that originate from the other categories are flat allow rules.
  _abstract_model.txt_ contains these rules and a list of the groups, each groups with the expression that defined
  it and the snapshot of the *VMs* in the group. 

 The following log files contain warning messages and various debug printing of the different stages
 of the synthesis, as following:

  * **runPreprocessing.log** Log of the stage in which the NSX rules are translated to symbolic rules.
  * **runConvertToAbstract.log** Log of the stage in which the symbolic rules from the preprocessing stage 
are translated to the abstract model's rules.  
  * **runK8SSynthesis.log** Log of the stage in which the k8s yaml pods and polices files are synthesized from 
the abstract model.
