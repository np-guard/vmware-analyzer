/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"strings"
	"testing"
)

func Test_main(t *testing.T) {
	tests := []struct {
		name    string
		args    string
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
			name: "error",
			args: "wergegsdtgh",
		},
		{
			name: "collect-only",
			args: "--host no_host --username no_user --password no_password --resource-dump-file resources.json --skip-analysis",
		},
		{
			name: "analyze-only",
			args: "--resource-input-file resources.json --dump-config-file analysis.txt",
		},
		{
			name: "collect-and-analyze",
			args: "--host no_host --username no_user --password no_password --resource-dump-file resources.json --dump-config-file analysis.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := _main(strings.Split(tt.args, " ")); err != nil {
				t.Errorf("_main() error = %v,", err)
			}
		})
	}
}
