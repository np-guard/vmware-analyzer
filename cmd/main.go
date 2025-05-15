/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/np-guard/vmware-analyzer/pkg/cli"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
)

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		_ = logging.InitDefault() // just in case it wasn't initialized earlier
		fmt.Fprintf(os.Stderr, "%v", err)
	}
}

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	return cli.Execute(cmdlineArgs)
}

/*


func main() {
	err := _main(os.Args[1:])
	if err != nil {
		_ = logging.Init(logging.MediumVerbosity, "") // just in case it wasn't initialized earlier
		fmt.Fprintf(os.Stderr, "%v", err)
	}
}
*/

/*
func Execute() {
	rootCmd := newCommandRoot()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
*/
