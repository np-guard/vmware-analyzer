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
			if args.Quiet && args.Verbose {
				return errors.New("-q and -v cannot be specified together")
			}
			return nil
		},
	}

	// define any flags and configuration settings

	c.PersistentFlags().StringVarP(&args.ResourceInputFile, resourceInputFileFlag, "r", "", resourceInputFileHelp)
	c.PersistentFlags().StringVar(&args.Host, hostFlag, "", hostHelp)
	c.PersistentFlags().StringVar(&args.User, userFlag, "", userHelp)
	c.PersistentFlags().StringVar(&args.Password, passwordFlag, "", passwordHelp)
	c.PersistentFlags().BoolVarP(&args.Quiet, quietFlag, "q", false, quietHelp)
	c.PersistentFlags().BoolVarP(&args.Verbose, verboseFlag, "v", false, verboseHelp)
	c.PersistentFlags().BoolVar(&args.Color, colorFlag, false, colorHelp)
	c.PersistentFlags().StringVar(&args.LogFile, logFileFlag, "", logFileHelp)
	c.PersistentFlags().BoolVar(&args.DisableInsecureSkipVerify, disableInsecureSkipVerifyFlag, false, disableInsecureSkipVerifyHelp)
	c.PersistentFlags().StringVar(&args.ResourceDumpFile, resourceDumpFileFlag, "", resourceDumpFileHelp)
	c.PersistentFlags().Var(&args.LogLevel, logLevelFlag, logLevelHelp+common.AllLogLevelOptionsStr)

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
