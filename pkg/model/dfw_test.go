package model

/*
import (
	"fmt"
	"testing"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
	"github.com/stretchr/testify/require"
)

var vmA = &vm{name: "A"}
var vmB = &vm{name: "B"}
var vmC = &vm{name: "C"}
var allVms = []*vm{vmA, vmB, vmC}

func allowRule(src, dst *vm, conn *connection.Set) *fwRule {
	return &fwRule{
		srcVMs: []*vm{src},
		dstVMs: []*vm{dst},
		conn:   conn,
		action: actionAllow,
	}
}

func denyRule(src, dst *vm, conn *connection.Set) *fwRule {
	return &fwRule{
		srcVMs: []*vm{src},
		dstVMs: []*vm{dst},
		conn:   conn,
		action: actionDeny,
	}
}

func tcp80Conn() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, 1, 65535, 80, 80)
}

func tcp443Conn() *connection.Set {
	return connection.TCPorUDPConnection(netp.ProtocolStringTCP, 1, 65535, 443, 443)
}

func newConfig(rules []*fwRule, defaultAction ruleAction) *config {
	return &config{
		vms: allVms,

		fw: &dfw{
			defaultAction: defaultAction,
			rules:         rules,
		},
	}
}

type testConnMap struct {
	name            string
	c               *config
	expectedConnMap connMap // for test (todo: move)
}

type connLine struct {
	src  *vm
	dst  *vm
	conn *connection.Set
}

func expectedConnMap(initAllow bool, c ...connLine) connMap {
	res := connMap{}
	res.initPairs(initAllow, allVms)
	for _, l := range c {
		res.add(l.src, l.dst, l.conn)
	}
	return res
}

func (test *testConnMap) run(t *testing.T) {
	expected := fmt.Sprintf("%v", test.expectedConnMap)
	connMapRes := test.c.getConnMap()
	actual := fmt.Sprintf("%v", connMapRes)
	require.Equal(t, expected, actual, "comparison failed between expected vs actual conn-map")
	fmt.Printf("%s\n", connMapRes.string())
	fmt.Printf("%v\n", connMapRes)
	fmt.Println("done")

}

var tests = []*testConnMap{
	{
		name: "deny by default, second allow rule masked by prior deny rule",
		c: newConfig([]*fwRule{
			allowRule(vmA, vmB, tcp80Conn()),
			denyRule(vmA, vmB, tcp443Conn()),
			allowRule(vmA, vmB, tcp443Conn()),
		},
			actionDeny, // default
		),

		expectedConnMap: expectedConnMap(false,
			connLine{vmA, vmB, tcp80Conn()},
		),
	},

	{
		name: "deny by default, 2 allow rules aggregated",
		c: newConfig([]*fwRule{
			allowRule(vmA, vmB, tcp80Conn()),
			allowRule(vmA, vmB, tcp443Conn()),
		},
			actionDeny, // default
		),

		expectedConnMap: expectedConnMap(false,
			connLine{vmA, vmB, tcp80Conn().Union(tcp443Conn())},
		),
	},

	{
		name: "allow by default, basic test with one deny rule",
		c: newConfig([]*fwRule{
			denyRule(vmA, vmB, tcp443Conn()),
		},
			actionAllow, // default
		),

		expectedConnMap: expectedConnMap(true,
			connLine{vmA, vmB, connection.All().Subtract(tcp443Conn())},
		),
	},

	{
		name: "allow by default,  second deny rule masked by prior allow rule",
		c: newConfig([]*fwRule{
			denyRule(vmA, vmB, tcp443Conn()),
			allowRule(vmA, vmB, tcp80Conn()),
			denyRule(vmA, vmB, tcp80Conn()),
		},
			actionAllow, // default
		),

		expectedConnMap: expectedConnMap(true,
			connLine{vmA, vmB, connection.All().Subtract(tcp443Conn())},
		),
	},

	{
		name: "allow by default,   2 deny rules aggregated",
		c: newConfig([]*fwRule{
			denyRule(vmA, vmB, tcp443Conn()),
			denyRule(vmA, vmB, tcp80Conn()),
		},
			actionAllow, // default
		),

		expectedConnMap: expectedConnMap(true,
			connLine{vmA, vmB, connection.All().Subtract(tcp443Conn()).Subtract(tcp80Conn())},
		),
	},

	{
		name: "allow rule with default allow",
		c: newConfig([]*fwRule{
			allowRule(vmA, vmB, tcp443Conn()),
		},
			actionAllow, // default
		),

		expectedConnMap: expectedConnMap(true),
	},

	{
		name: "deny rule with default deny",
		c: newConfig([]*fwRule{
			denyRule(vmA, vmB, tcp443Conn()),
		},
			actionDeny, // default
		),

		expectedConnMap: expectedConnMap(false),
	},
}

func TestBasic(t *testing.T) {

	t.Parallel()
	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			tests[i].run(t)
		})
	}
}
*/
