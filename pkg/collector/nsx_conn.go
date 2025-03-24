package collector

import (
	"fmt"
	"os"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func getNSXArg(arg *string, envVar string) error {
	if *arg != "" {
		return nil
	}
	*arg = os.Getenv(envVar)
	if *arg == "" {
		return fmt.Errorf(common.ErrMissingRquiredArg+" %s", envVar)
	}
	return nil
}

func GetNSXServerDate(host, user, password string, insecureSkipVerify bool) (ServerData, error) {
	// extract NSX credentials from cli args / env vars
	if err := getNSXArg(&host, "NSX_HOST"); err != nil {
		return ServerData{}, err
	}
	if err := getNSXArg(&user, "NSX_USER"); err != nil {
		return ServerData{}, err
	}
	if err := getNSXArg(&password, "NSX_PASSWORD"); err != nil {
		return ServerData{}, err
	}
	if os.Getenv("NSX_SKIP_VERIFY") == "true" {
		insecureSkipVerify = true
	}
	logging.Infof("collecting NSX resources from given host %s", host)
	return NewServerData(host, user, password, insecureSkipVerify), nil
}
