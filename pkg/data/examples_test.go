package data

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
)

// this test should be run to keep the example JSON files in-sync with examples defined here.
// comparing by parsing to config objects both JSON and example, and then based on config str comparison.
func TestUpdateModifiedExamplesInJSONFiles(t *testing.T) {
	for _, example := range allExamples {
		err := example.syncJSONWithExample()
		if err != nil {
			fmt.Printf("error for test %s: %s\n", example.Name, err.Error())
		}
		require.Nilf(t, err, example.Name)
	}
	fmt.Printf("done")
}

func (e *Example) syncJSONWithExample() error {
	if e.Name == "" {
		return fmt.Errorf("invalid example with empty name")
	}
	jsonPath := GetExamplesJSONPath(e.Name)
	var exampleConfig, jsonConfig *configuration.Config

	// get from example its parsed config object
	rc, err := ExamplesGeneration(e, false)
	if err != nil {
		return err
	}
	exampleConfig, err = configuration.ConfigFromResourcesContainer(rc, false)
	if err != nil {
		return err
	}

	// get from JSON its parsed config object

	b, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}
	rcFromJSON, err := collector.FromJSONString(b)
	if err != nil {
		return err
	}
	jsonConfig, err = configuration.ConfigFromResourcesContainer(rcFromJSON, false)
	if err != nil {
		return err
	}

	// compare both parsed configs that should be in-sync

	exampleConfigStr := exampleConfig.GetConfigInfoStr(false)
	jsonConfigStr := jsonConfig.GetConfigInfoStr(false)

	if exampleConfigStr != jsonConfigStr {
		// generating text files wilt config str - for easy comparison and gaps review
		err1 := common.WriteToFile(e.Name+"_example-config-str.txt", exampleConfigStr)
		err2 := common.WriteToFile(e.Name+"_json-config-str.txt", jsonConfigStr)
		if err := errors.Join(err1, err2); err != nil {
			fmt.Printf("error creating txt files for comparison of config gaps: %s", err.Error())
		}

		// sync is required if config json str is not the same
		fmt.Printf("sync required for example %s -- overriding JSON!\n", e.Name)
		err := e.storeAsJSON(true, rc)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("example %s json is already in sync\n", e.Name)
	}

	return nil
}

func TestDoNotAllowSameName(t *testing.T) {
	names := map[string]bool{}
	for _, example := range allExamples {
		require.NotEmpty(t, example.Name, "example name should not be empty")
		require.False(t, names[example.Name], "There are two examples with the same name %s", example.Name)
		names[example.Name] = true
	}
}
