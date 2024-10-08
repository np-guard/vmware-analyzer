/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"strings"
	"testing"
)

const serverInfo = "--host no_host --username no_user --password no_password"

func Test_main(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		// version
		{
			name: "version",
			args: "--version",
		},
		// help
		{
			name: "help",
			args: "-h",
		},
		{
			name: "collect-only",
			args: serverInfo + " --resource-dump-file examples/output/resources.json --skip-analysis",
		},
		{
			name: "analyze-only",
			args: "--resource-input-file examples/input/resources.json --filename examples/output/analysis.txt",
		},
		{
			name: "analyze-only-dot",
			args: "--resource-input-file examples/input/resources.json --filename examples/output/analysis.dot -o dot",
		},
		{
			name: "collect-and-analyze",
			args: serverInfo + " --resource-dump-file examples/output/resources2.json --filename examples/output/analysis2.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.args, serverInfo) {
				if err := _main(strings.Split(tt.args, " ")); err != nil {
					t.Errorf("_main() error = %v,", err)
				}
			}
		})
	}
}
