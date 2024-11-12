package synthesis

import (
	"fmt"
	"github.com/np-guard/vmware-analyzer/pkg/collector/data"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/stretchr/testify/require"
	"testing"
)

type synthesisTest struct {
	name   string
	exData data.Example
}

var allTests = []synthesisTest{
	{
		name:   "Example1",
		exData: data.Example1,
	},
	{
		name:   "Example2",
		exData: data.Example2,
	},
}

func (a *synthesisTest) file() string {
	return a.name + ".txt"
}

func (a *synthesisTest) run(t *testing.T) {
	//nolint:gocritic // comment here should stay
	fmt.Println()
	rc := data.ExamplesGeneration(a.exData)
	params := model.OutputParameters{
		Format: "txt",
	}
	err := SynthesisConfig(rc, params)
	require.Nil(t, err)
	fmt.Println("done")
}

func TestSynthesis(t *testing.T) {
	logging.Init(logging.HighVerbosity)
	for i := range allTests {
		test := &allTests[i]
		test.run(t)
	}
}