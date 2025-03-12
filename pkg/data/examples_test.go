package data

import (
	"fmt"
	"os"
	"testing"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/stretchr/testify/require"
)

// this test should be run to keep the example JSON files in-sync with examples defined here.
// comparing by parsing to config objects both JSON and example, and then based on config str comparison.
func TestUpdateModifiedExamplesInJSONFiles(t *testing.T) {
	for _, example := range allTests {
		err := example.syncJSONWithExample()
		require.Nilf(t, err, example.Name)
	}
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
		common.WriteToFile(e.Name+"_example-config-str.txt", exampleConfigStr)
		common.WriteToFile(e.Name+"_json-config-str.txt", jsonConfigStr)

		// sync is required if config json str is not the same
		fmt.Printf("sync required for example %s -- overriding JSON!\n", e.Name)
		err := e.storeAsJSON(true, rc)
		if err != nil {
			return err
		}
	}
	return nil
}

func TestDoNotAllowSameName(t *testing.T) {
	names := map[string]bool{}
	for _, example := range allTests {
		require.False(t, names[example.Name], "There are two examples with the same name %s", example.Name)
		names[example.Name] = true
	}
}
