## definitions ##
Let:

A *conjunction path* be a pair s, d where s and d each are conjunction of literals; the implied paths are all paths from an endpoint that satisfies s to an endpoint that satisfies d

*Or-conjunction paths* be the paths implied by the union of conjunction paths (“OR”ing the paths)

##Algorithm for computing a set of ORed allow paths from a single conjunction  allow path and higher priority conjunction deny path (implemented in computeAllowGivenAllowHigherDeny):

Input: allow conjunction path, a conjunction deny 

Output: or-conjunction allow paths

Consider the following input:

Allow path where each Si, Di is a conjunction

| Src           |      Dst |
|---------------|---------:|
| S1            |       D1 |

And conjunction deny path (`si` and `di` are a literal each):


| Src                        |                          Dst |
|----------------------------|-----------------------------:|
| s1' and s2' and ... and sn' |    d1 and d2 and ... dn`     |

The equivalent or-conjunction allow paths are:

| Src            |            Dst |
|----------------|---------------:|
| S1 and not s1` |             D1 |
| ....           |             D1 |
| S1 and not sn` |             D1 |
| S1             |  D1 and not d1` |
| ....           |            ... |
| S1             |  D1 and not dn` |

Note that S1 and/or D1 could be all paths (*), in which case S1 (D1) are replaced by *

And in case the conjunction deny path is open on one end:

| Src           | Dst |
|---------------|----:|
|s1' and s2' and ... and sn'     |   * |


The equivalent or-conjunction allow paths are:

| Src            |            Dst |
|----------------|---------------:|
| S1 and not s1` |             D1 |
| ....           |             D1 |
| S1 and not sn` |             D1 |

Similarly, for the case the deny path is open in the destination