package test_utils

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

// init debug level log without err for unit tests
func LogInit(t *testing.T, file string) {
	require.Nil(t, logging.Init(common.LogLevelDebug, ""))
}
