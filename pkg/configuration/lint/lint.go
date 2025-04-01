package lint

import (
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func LintReport(c *configuration.Config, color bool) string {
	// redundant rules analysis
	logging.Infof("Lint NSX config - produce redundant DFW rules report:")
	shadowedRules, _ := c.FW.RedundantRulesAnalysis(c.VMs, color)
	emptyRules := c.FW.IneffectiveRulesReport(color)
	if shadowedRules == "" && emptyRules == "" {
		return "No redundant DFW rules found."
	}
	return shadowedRules + "\n" + emptyRules
}
