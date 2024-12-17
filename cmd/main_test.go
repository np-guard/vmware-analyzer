/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(t *testing.T) {
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
			args: "--resource-dump-file examples/output/resources.json --skip-analysis",
		},
		{
			name: "collect-anonymize",
			args: "--resource-dump-file examples/output/resources_anon.json --skip-analysis --anonymize",
		},
		{
			name: "anonymize-only",
			args: "--resource-input-file examples/input/resources.json --resource-dump-file examples/output/resources_anon.json" +
				" --skip-analysis --anonymize",
		},
		/*{
			name: "anonymize-analyze",
			args: "--resource-input-file examples/input/resources.json --resource-dump-file examples/output/resources.json" +
				" --anonymize --filename examples/output/analysis.svg -o svg",
		},*/
		{
			name: "analyze-only",
			args: "--resource-input-file examples/input/resources.json --filename examples/output/analysis.txt",
		},
		{
			name: "analyze-topology-dot",
			args: "--resource-input-file examples/input/resources.json --topology-dump-file" +
				" examples/output/topology.dot --filename examples/output/analysis.dot -o dot",
		},
		{
			name: "analyze-topology-json",
			args: "--resource-input-file examples/input/resources.json --topology-dump-file" +
				" examples/output/topology.json --filename examples/output/analysis.json -o json",
		},
		{
			name: "analyze-topology-text",
			args: "--resource-input-file examples/input/resources.json --topology-dump-file" +
				" examples/output/topology.txt --filename examples/output/analysis.txt -o txt",
		},
		/*{
			name: "analyze-topology-svg",
			args: "--resource-input-file examples/input/resources.json --topology-dump-file" +
				" examples/output/topology.svg --filename examples/output/analysis.svg -o svg" +
				` --output-filter="New Virtual Machine",New-VM-1`,
		},*/
		{
			name: "collect-and-analyze",
			args: "--resource-dump-file examples/output/resources2.json --filename examples/output/analysis2.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverInfo := ""
			if !strings.Contains(tt.args, resourceInputFileFlag) {
				// you  can set your server info here:
				// serverInfo = "--host host --username user --password password "
				if serverInfo == "" && os.Getenv("NSX_HOST") == "" {
					fmt.Println("didn't got any server")
					return
				}
				serverInfo =
					fmt.Sprintf("--host %s --username %s --password %s ", os.Getenv("NSX_HOST"), os.Getenv("NSX_USER"), os.Getenv("NSX_PASSWORD"))
			}
			if err := _main(splitArgs(serverInfo + tt.args)); err != nil {
				t.Errorf("_main() error = %v,", err)
			}
		})
	}
}

func splitArgs(s string) []string {
	res := []string{}
	w := ""
	inQ := false
	for _, c := range s {
		switch {
		case c == '"':
			inQ = !inQ
		case c == ' ' && !inQ:
			res = append(res, w)
			w = ""
		default:
			w += string(c)
		}
	}
	if w != "" {
		res = append(res, w)
	}
	return res
}
