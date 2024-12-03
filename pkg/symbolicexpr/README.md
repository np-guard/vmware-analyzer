## definitions ##
Let:

A *conjunction path* be a pair s, d where s and d each are conjunction of literals; the implied paths are all paths from an endpoint that satisfies s to an endpoint that satisfies d

*Or-conjunction paths* be the paths implied by the union of conjunction paths (“OR”ing the paths)

##Algorithm for computing a set of ORed allow paths from a single conjunction  allow path and higher priority conjunction deny path:
(implemented in computeAllowGivenAllowHigherDeny)

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

## Algorithm for computing a set of ORed denys from a single deny and a set of higher priority ORed passes ##
(implemented in computeAllowGivenAllowHigherPasses)

The resulting denies are proceeded with allows of lower priority categories 

Input: or-conjunction pass paths with a conjunction deny

Output: or-conjunction deny paths

The or-conjunction deny paths are proceeded to the next category and treated as higher priority deny.

Given the following pass paths:

| Src   | Dst |
|-------|----:|
| P1    |  P2 |
| ..    |  .. |
| P2n-1 | P2n |

With the lower priority deny path:

| Src   | Dst |
|-------|----:|
| S1    |  D1 |

The equivalent or-conjunction deny paths are:


| Src            |                                    Dst |
|----------------|---------------------------------------:|
| S and not P1 and not P3 and …. not P2n-1 |                                      D |
| S  | D and not P2 and not P4 and …. not P2n |
| S and P1|                               D and P4 |
| S and P1|                                    ... |
|S and P1 |                              D and P2n |
| ... |                                    ... |
| S and Pn |                               D and P2 |
| S and Pn|                                    ... |
|S and Pn |                            D and P2n-2 |

Note that here all the higher priority passes must be considered together; we can consider each of them in isolation