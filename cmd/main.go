/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"
)

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	rootCmd := newRootCommand()
	rootCmd.SetArgs(cmdlineArgs)
	return rootCmd.Execute()
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
	}
}
