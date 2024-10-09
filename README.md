# vmware-analyzer

## About vmware-analyzer
This repo contains packages and a CLI for analyzing the network connectivity between VMs, as specified by various NSX resources.

## Usage
Run the `nsxanalyzer` CLI tool.

```
$ ./bin/nsxanalyzer -h
nsxanalyzer is a CLI for collecting NSX resources, and analyzing permitted connectivity between VMs.
It uses REST API calls from NSX manager.

Usage:
  nsxanalyzer [flags]

Flags:
  -f, --filename string              file path to store analysis results
  -h, --help                         help for nsxanalyzer
      --host string                  nsx host url
  -o, --output string                output format; must be one of [txt, dot] (default "txt")
      --password string              nsx password
      --resource-dump-file string    file path to store collected resources in JSON format
      --resource-input-file string   file path input JSON of NSX resources
      --skip-analysis                flag to skip analysis, run only collector
      --username string              nsx username
  -v, --version                      version for nsxanalyzer
```

## Build the project

Make sure you have golang 1.23+ on your platform

```commandline
git clone git@github.com:np-guard/vmware-analyzer.git
cd vmware-analyzer
make mod 
make build
```

Test your build by running `./bin/vpcanalyzer -h`.