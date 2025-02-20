# Synthesize k8s policy

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
Synthesize a given NSX DFW configuration, specifically firewall rules, into an equivalent k8s network policy.
There are two main challenges here: 
* *The flattening challenge*: translating allow/deny/pass with priorities into flat allow rules (which is what k8s network policies support)
* *The intent preserving challenge*: maintain the original semantic intent of the rules, and not just synthesis a snapshot. 
This is important since once new e.g. VMs are added with the relevant tags/labels they should be granted the desired communication permissions and the 
desired protection.

### The flattening challenge
The translation of priortized allow/deny/pass rules into flat allow rules is exponential in the number of terms of the
original rules (to be accurate, the number of allow rules generated for each original allow rule is
exponential in the number of term in this allow rule and in higher priority deny and pass rules). To tackle this we:
1. Ask the user to provide the tool with lists - _hints_ -  of disjoint tags/groups. In the future it is planned to "guess" these
disjoint sets, and ask the user to approve them.
2. Apply various optimization to simplify the resulting rules and to rid redundant rules; the more accurate hints the
tool is provided, the more efficient the hints are 

### The policy preserving challenge
To preserve the original intent of the policy, the synthesized policy refers, where possible, to permanent labeling such
as tags - e.g. _front-end_ - and not to temporarily labeling such as _VM_ names. E.g., a specific rule's _src_ is
 defined to be group _aaa_ that is defined as _tag = backend_ and _tag != DB_ then the synthesized policy will refer to the value
of the tag.

## Currently supported
Currently the tool supports groups defined by expressions over tags; nested expression are not supported at the moment.
If a group is defined 
by an expression that we do not yet support, then the synthesized policy will refer just to the group, and the 
relevant *VM*s will be granted labels of this group. In the following releases we will expend our expressions support. 

## Debuging
The tool first translates the priortized allow/deny/pass rules into an abstract model that 
contains the rules to be syntactically translated to k8s policies; if _synthesize-admin-policies_  is off then all rules must 
be flat allow rules, and so all the rules in the abstract model are allow rules;
otherwise rules originating from _environment_ category are translated to admin policies and as such may also contain
priorties, allow, deny and pass; other rules are flat allow rules. Each rule is defined over
_src_, _dst_ and a _connection_. The rules are "Or"ed. 
The _src_ and the _dst_ are _Conjunction_, and the _connection_ contains a protocol and potentially _src/dst_ ports.
The synthesis dump directory contains the abstract model, in addition to other debug data, such as the connectivity map.   