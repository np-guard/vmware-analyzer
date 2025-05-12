package anonymizer

import (
	"testing"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func TestInit(*testing.T) {
	if *common.Update {
		logging.Debugf("flag update is ture")
	}
}
