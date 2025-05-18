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


generated 15 network policies
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


generated 10 network policies
```

### Automatic inference of disjoint groups

The flag ` --hints-inference` can be used with the `generate` command, for automatic inference of NSX groups/tags that can be considered as disjoint.
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

