## Migration example - policy generation

### Rules flattening

Original DFW rules
```
ruleID |ruleName                  |src                  |dst          |services |action |direction |scope |sec-policy             |Category
1027   |foo-allow-http-to-backend |foo-frontend         |foo-backend  |HTTP     |allow  |IN_OUT    |ANY   |foo-app                |Application
1028   |default-deny-foo-app      |foo-app              |foo-app      |ANY      |deny   |IN_OUT    |ANY   |foo-app                |Application
1025   |allow-smb-to-foo-frontend |research-test-expr-2 |foo-frontend |SMB      |allow  |IN_OUT    |ANY   |New Policy             |Application
1024   |allow-bar-app-https       |bar-app              |bar-app      |HTTPS    |allow  |IN_OUT    |ANY   |New Policy             |Application
1021   |deny-research-app         |research-app         |research-app |ANY      |deny   |IN_OUT    |ANY   |Default Layer3 Section |Application
2      |default-deny-rule         |ANY                  |ANY          |ANY      |deny   |IN_OUT    |ANY   |Default Layer3 Section |Application

```

For network policy generation - flattening as "allow-only" rules **without** priorities.

Running:
```
$ nsxanalyzer generate -r pkg/data/json/ExampleAppWithGroupsAndSegments.json -v 
```


```
Allow Only Rules
~~~~~~~~~~~~~~~~~
inbound rules
Original allow rule priority |Rule id |Src                                                 |Dst                                         |Connection
0                            |1027    |(group = foo-frontend)                              |(group = foo-backend)                       |TCP dst-ports: 80
1                            |1025    |(group = research-test-expr-2 and group != foo-app) |(group = foo-frontend)                      |TCP dst-ports: 445
1                            |1025    |(group = research-test-expr-2)                      |(group = foo-frontend and group != foo-app) |TCP dst-ports: 445
2                            |1024    |(group = bar-app and group != foo-app)              |(group = bar-app)                           |TCP dst-ports: 443
2                            |1024    |(group = bar-app)                                   |(group = bar-app and group != foo-app)      |TCP dst-ports: 443

outbound rules
Original allow rule priority |Rule id |Src                                                 |Dst                                         |Connection
0                            |1027    |(group = foo-frontend)                              |(group = foo-backend)                       |TCP dst-ports: 80
1                            |1025    |(group = research-test-expr-2 and group != foo-app) |(group = foo-frontend)                      |TCP dst-ports: 445
1                            |1025    |(group = research-test-expr-2)                      |(group = foo-frontend and group != foo-app) |TCP dst-ports: 445
2                            |1024    |(group = bar-app and group != foo-app)              |(group = bar-app)                           |TCP dst-ports: 443
2                            |1024    |(group = bar-app)                                   |(group = bar-app and group != foo-app)      |TCP dst-ports: 443


generated 11 network policies
```




### Disjoint groups optimization

Consider the group definitions for this example:

```
Group Name           |VMs
bar-app              |New-VM-1, New-VM-2, New Virtual Machine
foo-app              |New-VM-3, New-VM-4
foo-backend          |New-VM-4
foo-frontend         |New-VM-3
research-app         |New-VM-1, New-VM-2, New-VM-3, New-VM-4, New Virtual Machine
research-test-expr-2 |New-VM-1
```

* The expression `(group = research-test-expr-2 and group != foo-app) ` can be simplified to `(group = research-test-expr-2)` if these groups never intersect.
* The expression `(group = bar-app and group != foo-app)` can be simplified to `(group = bar-app)` if these groups never intersect.

Running with disjoint hints:

```
$ nsxanalyzer generate -r pkg/data/json/ExampleAppWithGroupsAndSegments.json -v   --disjoint-hint research-test-expr-2,foo-app --disjoint-hint bar-app,foo-app
```

Will produce a simplified policy definition:

```
Allow Only Rules
~~~~~~~~~~~~~~~~~
inbound rules
Original allow rule priority |Rule id |Src                            |Dst                    |Connection
0                            |1027    |(group = foo-frontend)         |(group = foo-backend)  |TCP dst-ports: 80
1                            |1025    |(group = research-test-expr-2) |(group = foo-frontend) |TCP dst-ports: 445
2                            |1024    |(group = bar-app)              |(group = bar-app)      |TCP dst-ports: 443

outbound rules
Original allow rule priority |Rule id |Src                            |Dst                    |Connection
0                            |1027    |(group = foo-frontend)         |(group = foo-backend)  |TCP dst-ports: 80
1                            |1025    |(group = research-test-expr-2) |(group = foo-frontend) |TCP dst-ports: 445
2                            |1024    |(group = bar-app)              |(group = bar-app)      |TCP dst-ports: 443


generated 8 network policies
```

### Automatic inference of disjoint groups

The flag `--hints-inference` can be used with the `generate` command, for automatic inference of NSX groups/tags that can be considered as disjoint.
This optimizes the generated policies expressions, and can result in fewer generated policies with simpler selector expressions.
The inference is based on the current state of the NSX configuration. Thus, it is recommended to reveiew the inferred disjoint groups.

For the example above, running with this flag:

```
$ nsxanalyzer generate -r pkg/data/json/ExampleAppWithGroupsAndSegments.json --hints-inference  -v
```

Will produce the same simplified policy definition:

```
Allow Only Rules
~~~~~~~~~~~~~~~~~
inbound rules
Original allow rule priority |Rule id |Src                            |Dst                    |Connection
0                            |1027    |(group = foo-frontend)         |(group = foo-backend)  |TCP dst-ports: 80
1                            |1025    |(group = research-test-expr-2) |(group = foo-frontend) |TCP dst-ports: 445
2                            |1024    |(group = bar-app)              |(group = bar-app)      |TCP dst-ports: 443

outbound rules
Original allow rule priority |Rule id |Src                            |Dst                    |Connection
0                            |1027    |(group = foo-frontend)         |(group = foo-backend)  |TCP dst-ports: 80
1                            |1025    |(group = research-test-expr-2) |(group = foo-frontend) |TCP dst-ports: 445
2                            |1024    |(group = bar-app)              |(group = bar-app)      |TCP dst-ports: 443


generated 8 network policies
```

and the log will also report what disjoint groups were inferred:

```
Disjoint Groups' (hints)
~~~~~~~~~~~~~~~~~~~~~~~~
no disjoint groups' hints provided by user
Automatically inferred based on groups' snapshot
bar-app, foo-app
bar-app, foo-backend
bar-app, foo-frontend
foo-app, research-test-expr-2
foo-backend, foo-frontend
foo-backend, research-test-expr-2
foo-frontend, research-test-expr-2
```

### Partial migration option 

For the run with `--output-filter`, will focus only on these VMs in abstract rules and policy resource generation:

```
nsxanalyzer generate -r pkg/data/json/ExampleAppWithGroupsAndSegments.json -v --output-filter "New-VM-3,New-VM-4"
```

Will produce the following policy definition:

```
Allow Only Rules
~~~~~~~~~~~~~~~~~
inbound rules
Original allow rule priority |Rule id |Src                    |Dst                   |Connection
0                            |1027    |(group = foo-frontend) |(group = foo-backend) |TCP dst-ports: 80

outbound rules
Original allow rule priority |Rule id |Src                    |Dst                   |Connection
0                            |1027    |(group = foo-frontend) |(group = foo-backend) |TCP dst-ports: 80


generated 3 network policies
```


### Policy opimization level

The flag `--policy-optimization-level` has various options: `none / moderate / max`.

`none` – No optimization applied.

`moderate` – Conservative optimization, prioritizing correctness and minimal risk.

`max` – Strong optimization, may risk omitting required policies.

**Involved optimizations description:**

The original NSX groups and their symbolic expressions are defined globally and not per `namespaces` that exist in OCP-Virt.
The generated k8s policies define migrated expressions over label-selectors, for which namespace scope is required. 
The tool defines 3 levels of such migration with regard to namespaces applied, through the flag `--policy-optimization-level`.
For the `none` option, all namespaces are considered, for any original NSX symbolic group expression.
For the `moderate` option, the namespaces considered are the union of namespaces inferred as relevant for the terms in the NSX symbolic group expression.
A namespace is inferred as relevant for a term expression, if there is at least one VM matching this expression and mapped to this namespace.
For the `max` option, the namespaces considered are the intersection of namespaces inferred as relevant for the terms in the NSX symbolic group expression.


Below is an example of the resulting policies, given the three options above.

```
$ nsxanalyzer generate -r pkg/data/json/ExampleAppWithGroupsAndSegments.json   --policy-optimization-level none
```

```
INFO        generated 22 network policies
Policies details:
NAMESPACE      |NAME                            |POD-SELECTOR
T1-192-168-0-0 |default-deny-for-T1-192-168-0-0 |{}
T1-192-168-0-0 |policy-0                        |{Key:group__foo-frontend,Operator:Exists}
T1-192-168-0-0 |policy-10                       |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__foo-frontend,Operator:Exists}
T1-192-168-0-0 |policy-12                       |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
T1-192-168-0-0 |policy-14                       |{Key:group__bar-app,Operator:Exists}
T1-192-168-0-0 |policy-16                       |{Key:group__bar-app,Operator:Exists}
T1-192-168-0-0 |policy-18                       |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
T1-192-168-0-0 |policy-2                        |{Key:group__foo-backend,Operator:Exists}
T1-192-168-0-0 |policy-4                        |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__research-test-expr-2,Operator:Exists}
T1-192-168-0-0 |policy-6                        |{Key:group__research-test-expr-2,Operator:Exists}
T1-192-168-0-0 |policy-8                        |{Key:group__foo-frontend,Operator:Exists}
T1-192-168-1-0 |default-deny-for-T1-192-168-1-0 |{}
T1-192-168-1-0 |policy-1                        |{Key:group__foo-frontend,Operator:Exists}
T1-192-168-1-0 |policy-11                       |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__foo-frontend,Operator:Exists}
T1-192-168-1-0 |policy-13                       |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
T1-192-168-1-0 |policy-15                       |{Key:group__bar-app,Operator:Exists}
T1-192-168-1-0 |policy-17                       |{Key:group__bar-app,Operator:Exists}
T1-192-168-1-0 |policy-19                       |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
T1-192-168-1-0 |policy-3                        |{Key:group__foo-backend,Operator:Exists}
T1-192-168-1-0 |policy-5                        |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__research-test-expr-2,Operator:Exists}
T1-192-168-1-0 |policy-7                        |{Key:group__research-test-expr-2,Operator:Exists}
T1-192-168-1-0 |policy-9                        |{Key:group__foo-frontend,Operator:Exists}
```

Note here, that policies with selector `{Key:group__foo-frontend,Operator:Exists}` are generated for both namespaces `T1-192-168-0-0` and `T1-192-168-1-0`,
although there is no VM matching this expression which is mapped to the namespace `T1-192-168-1-0`.
For both `moderate` and `max` optimization levels those policies would not have been generated (is it an expression with single term, so both union and intersection of a single namespace are the same here.)


```
$ nsxanalyzer generate -r pkg/data/json/ExampleAppWithGroupsAndSegments.json   --policy-optimization-level moderate
```


```
INFO        generated 13 network policies

Policies details:
NAMESPACE      |NAME                            |POD-SELECTOR
T1-192-168-0-0 |default-deny-for-T1-192-168-0-0 |{}
T1-192-168-0-0 |policy-0                        |{Key:group__foo-frontend,Operator:Exists}
T1-192-168-0-0 |policy-1                        |{Key:group__foo-backend,Operator:Exists}
T1-192-168-0-0 |policy-4                        |{Key:group__foo-frontend,Operator:Exists}
T1-192-168-0-0 |policy-5                        |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__foo-frontend,Operator:Exists}
T1-192-168-1-0 |default-deny-for-T1-192-168-1-0 |{}
T1-192-168-1-0 |policy-10                       |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
T1-192-168-1-0 |policy-2                        |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__research-test-expr-2,Operator:Exists}
T1-192-168-1-0 |policy-3                        |{Key:group__research-test-expr-2,Operator:Exists}
T1-192-168-1-0 |policy-6                        |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__foo-frontend,Operator:Exists}
T1-192-168-1-0 |policy-7                        |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
T1-192-168-1-0 |policy-8                        |{Key:group__bar-app,Operator:Exists}
T1-192-168-1-0 |policy-9                        |{Key:group__bar-app,Operator:Exists}
```

Note here, that policies with selector `{Key:group__foo-app,Operator:DoesNotExist},{Key:group__foo-frontend,Operator:Exists}` are generated for both namespaces `T1-192-168-0-0` and `T1-192-168-1-0`, although there is no VM in the intersection of the mapped namespaces. The first term has VMs mapped to one namespace, and the second term has VMs mapped to another namespace.
For the `max` optimization level, those policies would not have been generated.


```
$ nsxanalyzer generate -r pkg/data/json/ExampleAppWithGroupsAndSegments.json   --policy-optimization-level max
```

```
INFO        generated 10 network policies

Policies details:
NAMESPACE      |NAME                            |POD-SELECTOR
T1-192-168-0-0 |default-deny-for-T1-192-168-0-0 |{}
T1-192-168-0-0 |policy-0                        |{Key:group__foo-frontend,Operator:Exists}
T1-192-168-0-0 |policy-1                        |{Key:group__foo-backend,Operator:Exists}
T1-192-168-0-0 |policy-3                        |{Key:group__foo-frontend,Operator:Exists}
T1-192-168-1-0 |default-deny-for-T1-192-168-1-0 |{}
T1-192-168-1-0 |policy-2                        |{Key:group__foo-app,Operator:DoesNotExist},{Key:group__research-test-expr-2,Operator:Exists}
T1-192-168-1-0 |policy-4                        |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
T1-192-168-1-0 |policy-5                        |{Key:group__bar-app,Operator:Exists}
T1-192-168-1-0 |policy-6                        |{Key:group__bar-app,Operator:Exists}
T1-192-168-1-0 |policy-7                        |{Key:group__bar-app,Operator:Exists},{Key:group__foo-app,Operator:DoesNotExist}
```

The `max` optimization level generates the smallest number of network policies.
The risk is that some policies should be defined across namespaces that are not reflected by the state of VMs mapped to namespaces.
In this example the policy with selector `{Key:group__foo-app,Operator:DoesNotExist},{Key:group__foo-frontend,Operator:Exists}` is not generated, because there are no actual VMs in a common namespace that satisfy this expression.

Additionally, policy `policy-3` from the `moderate` run is not generated for ths `max` optimization level, this time because of the rule peers. 
The rule peers expression is `(group = foo-frontend and group != foo-app)`, for which the same optimization infers an empty set of relevant namespaces.
Thus, the policy has no rules and therefore it is not generated.


