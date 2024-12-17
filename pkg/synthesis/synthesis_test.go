package synthesis

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
)

type synthesisTest struct {
	name   string
	exData data.Example
}

var allTests = []synthesisTest{
	{
		name:   "ExampleDumb",
		exData: data.ExampleDumb,
	},
}

func (a *synthesisTest) run(t *testing.T) {
	params := model.OutputParameters{
		Format: "txt",
	}
	rc := data.ExamplesGeneration(a.exData)
	res, err := NSXSynthesis(rc, params)
	require.Nil(t, err)
	fmt.Println(res)
}

func TestSynthesis(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		test.run(t)
	}
}
