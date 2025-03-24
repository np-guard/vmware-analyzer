package common

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/ds"
	"github.com/np-guard/models/pkg/interval"
	"github.com/np-guard/models/pkg/netset"
)

// TODO: move this type and methods to `models` repo

// DiscreteEndpointsTrafficSet captures a set of traffic attributes for tuples of (source endpoints, desination endpoints, TransportSet),
// where TransportSet is a set of TCP/UPD/ICMP with their properties (src,dst ports / icmp type,code)
// and source/destination endpoints are from a discrete set represented by integer IDs (could be mapped to VMs UIDs / Pod UIDs, etc.. )
type DiscreteEndpointsTrafficSet struct {
	props ds.TripleSet[*interval.CanonicalSet, *interval.CanonicalSet, *netset.TransportSet]
}

// EmptyDiscreteEndpointsTrafficSet returns an empty SimpleEndpointsTrafficSet
func EmptyDiscreteEndpointsTrafficSet() *DiscreteEndpointsTrafficSet {
	return &DiscreteEndpointsTrafficSet{props: ds.NewLeftTripleSet[*interval.CanonicalSet, *interval.CanonicalSet, *netset.TransportSet]()}
}

// Equal returns true is this SimpleEndpointsTrafficSet captures the exact same set of connections as `other` does.
func (c *DiscreteEndpointsTrafficSet) Equal(other *DiscreteEndpointsTrafficSet) bool {
	return c.props.Equal(other.props)
}

// Copy returns new SimpleEndpointsTrafficSet object with same set of connections as current one
func (c *DiscreteEndpointsTrafficSet) Copy() *DiscreteEndpointsTrafficSet {
	return &DiscreteEndpointsTrafficSet{
		props: c.props.Copy(),
	}
}

// Intersect returns a SimpleEndpointsTrafficSet object with connection tuples that result from intersection of
// this and `other` sets
func (c *DiscreteEndpointsTrafficSet) Intersect(other *DiscreteEndpointsTrafficSet) *DiscreteEndpointsTrafficSet {
	return &DiscreteEndpointsTrafficSet{props: c.props.Intersect(other.props)}
}

// IsEmpty returns true of the SimpleEndpointsTrafficSet is empty
func (c *DiscreteEndpointsTrafficSet) IsEmpty() bool {
	return c.props.IsEmpty()
}

// Union returns a SimpleEndpointsTrafficSet object with connection tuples that result from union of
// this and `other` sets
func (c *DiscreteEndpointsTrafficSet) Union(other *DiscreteEndpointsTrafficSet) *DiscreteEndpointsTrafficSet {
	if other.IsEmpty() {
		return c.Copy()
	}
	if c.IsEmpty() {
		return other.Copy()
	}
	return &DiscreteEndpointsTrafficSet{
		props: c.props.Union(other.props),
	}
}

// Subtract returns a SimpleEndpointsTrafficSet object with connection tuples that result from subtraction of
// `other` from this set
func (c *DiscreteEndpointsTrafficSet) Subtract(other *DiscreteEndpointsTrafficSet) *DiscreteEndpointsTrafficSet {
	if other.IsEmpty() {
		return c.Copy()
	}
	return &DiscreteEndpointsTrafficSet{props: c.props.Subtract(other.props)}
}

// IsSubset returns true if c is subset of other
func (c *DiscreteEndpointsTrafficSet) IsSubset(other *DiscreteEndpointsTrafficSet) bool {
	return c.props.IsSubset(other.props)
}

// NewDiscreteEndpointsTrafficSet returns a new SimpleEndpointsTrafficSet object from input src, dst endpoint sets ands
// TransportSet connections
func NewDiscreteEndpointsTrafficSet(src, dst *interval.CanonicalSet, conn *netset.TransportSet) *DiscreteEndpointsTrafficSet {
	return &DiscreteEndpointsTrafficSet{props: ds.CartesianLeftTriple(src, dst, conn)}
}

func (c *DiscreteEndpointsTrafficSet) Partitions() []ds.Triple[*interval.CanonicalSet, *interval.CanonicalSet, *netset.TransportSet] {
	return c.props.Partitions()
}

func simplecubeStr(c ds.Triple[*interval.CanonicalSet, *interval.CanonicalSet, *netset.TransportSet]) string {
	return fmt.Sprintf("src: %s, dst: %s, conns: %s", c.S1.String(), c.S2.String(), c.S3.String())
}

func (c *DiscreteEndpointsTrafficSet) String() string {
	if c.IsEmpty() {
		return "<empty>"
	}
	cubes := c.Partitions()
	var resStrings = make([]string, len(cubes))
	for i, cube := range cubes {
		resStrings[i] = simplecubeStr(cube)
	}
	sort.Strings(resStrings)
	return strings.Join(resStrings, CommaSeparator)
}
