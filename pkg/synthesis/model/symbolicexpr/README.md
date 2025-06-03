## definitions ##
Let:

A *term path* be a pair s, d where s and d each are term of literals; the implied paths are all paths from an endpoint that satisfies s to an endpoint that satisfies d

*DNF paths* be the paths implied by the union of term paths (“OR”ing the paths)

##Algorithm for computing a set of ORed allow paths from a single term  allow path and higher priority term deny path (implemented in computeAllowGivenAllowHigherDeny):

Input: allow term path, a term deny 

Output: dnf allow paths

Consider the following input:

Allow path where each Si, Di is a term

| Src           |      Dst |
|---------------|---------:|
| S1            |       D1 |

And term deny path (`si` and `di` are a literal each):


| Src                        |                          Dst |
|----------------------------|-----------------------------:|
| s1' and s2' and ... and sn' |    d1 and d2 and ... dn`     |

The equivalent DNF allow paths are:

| Src            |            Dst |
|----------------|---------------:|
| S1 and not s1` |             D1 |
| ....           |             D1 |
| S1 and not sn` |             D1 |
| S1             |  D1 and not d1` |
| ....           |            ... |
| S1             |  D1 and not dn` |

Note that S1 and/or D1 could be all paths (*), in which case S1 (D1) are replaced by *

And in case the term deny path is open on one end:

| Src           | Dst |
|---------------|----:|
|s1' and s2' and ... and sn'     |   * |


The equivalent DNF allow paths are:

| Src            |            Dst |
|----------------|---------------:|
| S1 and not s1` |             D1 |
| ....           |             D1 |
| S1 and not sn` |             D1 |

Similarly, for the case the deny path is open in the destination

## optimization in code:
Function func _ComputeAllowGivenDenies(allowPaths, denyPaths *SymbolicPaths, hints *Hints) *SymbolicPaths_ 
has two optimizations: 
# optimization 1
Before the actual computation for each "allow path" and "deny paths", the optimization drops "deny paths" that
are disjoint to the "allow path"; e.g. 
"allow": a to b on TCP ; "deny": c to d on UDP - in this case the "deny" has no effect
# optimization 2:
After the computation of all the "flat allow paths", paths that are subset of other "flat allow paths" are dropped

Function _func computeAllowGivenAllowHigherDeny(allowPath, denyPath SymbolicPath, hints *Hints) *SymbolicPaths_
also has two optimizations
# optimization 3:
At the end of the computation empty paths are removed. For example:
"allow": s to d on TCP "deny": s to e on TCP -  will result, among other paths, in the path 
"(s and not s) to d on TCP" which is empty and can clearly be removed
# optimization 4:
Immediately after the previous optimization, redundant terms are removed from the src term and dst term 
of the (non-empty) paths.
A term is redundant in a term if it is a tautology or is a subset of another term in the term given the hints;
e.g. given that Slytherin and Gryffindor are disjoint, Gryffindor is a subset of !Slytherin 


# optimization 4: