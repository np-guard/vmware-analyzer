package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/version"
)

// newCommandRoot returns a cobra command with the appropriate configuration, flags and sub-commands to run the root command k8snetpolicy
func newCommandRoot() *cobra.Command {
	c := &cobra.Command{
		Use: "nsxanalyzer",
		Short: `nsxanalyzer is a CLI for collecting NSX resources, analysis of permitted connectivity between VMs,
and generation of k8s network policies`,
		Long: `nsxanalyzer is a CLI for collecting NSX resources, analysis of permitted connectivity between VMs,
and generation of k8s network policies. It uses REST API calls from NSX manager. `,
		Version: version.VersionCore,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if args.quiet && args.verbose {
				return errors.New("-q and -v cannot be specified together")
			}
			return nil
		},
	}

	// define any flags and configuration settings

	c.PersistentFlags().StringVarP(&args.resourceInputFile, resourceInputFileFlag, "r", "", resourceInputFileHelp)
	c.PersistentFlags().StringVar(&args.host, hostFlag, "", hostHelp)
	c.PersistentFlags().StringVar(&args.user, userFlag, "", userHelp)
	c.PersistentFlags().StringVar(&args.password, passwordFlag, "", passwordHelp)
	c.PersistentFlags().BoolVarP(&args.quiet, quietFlag, "q", false, quietHelp)
	c.PersistentFlags().BoolVarP(&args.verbose, verboseFlag, "v", false, verboseHelp)
	c.PersistentFlags().BoolVar(&args.color, colorFlag, false, colorHelp)
	c.PersistentFlags().StringVar(&args.logFile, logFileFlag, "", logFileHelp)
	c.PersistentFlags().BoolVar(&args.disableInsecureSkipVerify, disableInsecureSkipVerifyFlag, false, disableInsecureSkipVerifyHelp)
	c.PersistentFlags().StringVar(&args.resourceDumpFile, resourceDumpFileFlag, "", resourceDumpFileHelp)
	c.PersistentFlags().Var(&args.logLevel, logLevelFlag, logLevelHelp+common.AllLogLevelOptionsStr)

	// add sub-commands
	c.AddCommand(newCommandCollect())
	c.AddCommand(newCommandAnalyze())
	c.AddCommand(newCommandGenerate())
	c.AddCommand(newCommandLint())

	return c
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(cmdlineArgs []string) error {
	args = newInArgs()
	rootCmd := newCommandRoot()
	rootCmd.SetArgs(cmdlineArgs)
	return rootCmd.Execute()
}
