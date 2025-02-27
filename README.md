# vmware-analyzer

## About vmware-analyzer
This repo contains packages and a CLI for NSX DFW analysis and k8s network policy synthesis.
It includes analysis of the network connectivity between VMs, as specified by various NSX resources.
It also includes functionality to synthesize k8s network policies, that preserve the micro-segmentation configured by NSX DFW.


## Usage
Run the `nsxanalyzer` CLI tool.

```
$ ./bin/nsxanalyzer -h
nsxanalyzer is a CLI for collecting NSX resources, analysis of permitted connectivity between VMs,
and generation of k8s network policies. It uses REST API calls from NSX manager.

Usage:
  nsxanalyzer [flags]

Flags:
      --anonymize                    flag to anonymize collected NSX resources (default false)
      --color                        flag to enable color output (default false)
      --disjoint-hint stringArray    comma separated list of NSX groups/tags that are always disjoint in their VM members, needed for an effective and sound synthesis process, can specify more than one hint (example: "--disjoint-hint frontend,backend --disjoint-hint app,web,db")
  -e, --explain                      flag to explain connectivity output with rules explanations per allowed/denied connections (default false)
  -f, --filename string              file path to store analysis results
  -h, --help                         help for nsxanalyzer
      --host string                  NSX host URL. Alternatively, set the host via the NSX_HOST environment variable
      --log-file string              file path to write nsxanalyzer log
  -o, --output string                output format; must be one of txt,dot,svg,json (default "txt")
      --output-filter strings        filter the analysis results by vm names, can specify more than one (example: "vm1,vm2")
      --password string              NSX password. Alternatively, set the password via the NSX_PASSWORD environment variable
  -q, --quiet                        flag to run quietly, report only severe errors and result (default false)
      --resource-dump-file string    file path to store collected resources in JSON format
  -r, --resource-input-file string   file path input JSON of NSX resources (instead of collecting from NSX host)
      --skip-analysis                flag to skip analysis, run only collector and/or synthesis (default false)
      --synth-create-dns-policy     flag to create a policy allowing access to target env dns pod (default true)
      --synthesis-dump-dir string    apply synthesis; specify directory path to store k8s synthesis results
      --synthesize-admin-policies    include admin network policies in policy synthesis (default false)
      --topology-dump-file string    file path to store topology
      --username string              NSX username. Alternatively, set the username via the NSX_USER environment variable
  -v, --verbose                      flag to run with more informative messages printed to log (default false)
      --version                      version for nsxanalyzer
```

## Example connectivity analysis output

### Textual permitted connectivity
```
$ nsxanalyzer --resource-input-file pkg/data/json/Example2.json 

Analyzed connectivity:
Source         |Destination    |Permitted connections
Dumbledore1    |Gryffindor-Web |TCP dst-ports: 80,443
Dumbledore1    |Hufflepuff-Web |TCP dst-ports: 80,443
Dumbledore1    |Slytherin-Web  |TCP dst-ports: 80,443
Dumbledore2    |Gryffindor-Web |TCP dst-ports: 80,443
Dumbledore2    |Hufflepuff-Web |TCP dst-ports: 80,443
Dumbledore2    |Slytherin-Web  |TCP dst-ports: 80,443
Gryffindor-App |Gryffindor-DB  |TCP dst-ports: 445
Gryffindor-App |Gryffindor-Web |TCP dst-ports: 80,443
Gryffindor-App |Hufflepuff-App |All Connections
Gryffindor-App |Hufflepuff-Web |TCP dst-ports: 80,443
Gryffindor-App |Slytherin-Web  |TCP dst-ports: 80,443
...

```

### Visualized permitted connectivity
```
$ nsxanalyzer --resource-input-file pkg/data/json/Example2.json --output-filter Gryffindor-App,Gryffindor-DB,Gryffindor-Web,Dumbledore1 -o svg -f ex2Filter1.svg

```
![graph](pkg/analyzer/tests_expected_output/ex2Filter1.svg)



## Example k8s network policy synthesis

Original NSX DFW config: (see `pkg/data/json/Example1.json`)
```
ruleID |ruleName           |src      |dst     |conn |action |direction |scope |sec-policy |Category
1004   |allow_smb_incoming |frontend |backend |SMB  |allow  |IN_OUT    |ANY   |app-x      |Application
1003   |default-deny-rule  |ANY      |ANY     |ANY  |deny   |IN_OUT    |ANY   |app-x      |Application
```

Run policy synthesis:

```
$ nsxanalyzer -r pkg/data/json/Example1.json --skip-analysis --synthesis-dump-dir ex1-synth/
```

Example policy generated (1 out of 3): (see `ex1-synth/k8s_resources/policies.yaml` )

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
    annotations:
        description: 'TCP dst-ports: 445 from (group = frontend) to (group = backend)'
        nsx-id: "1004"
    creationTimestamp: null
    name: policy_0
spec:
    egress:
        - ports:
            - port: 445
              protocol: TCP
          to:
            - podSelector:
                matchExpressions:
                    - key: group__backend
                      operator: Exists
    podSelector:
        matchExpressions:
            - key: group__frontend
              operator: Exists
    policyTypes:
        - Egress
```

More details [here](README_Synthesis.md)


## NSX Supported API versions and resources
See documentation [here](docs/nsx_support.md).

## Build the project

Make sure you have golang 1.23+ on your platform

```commandline
git clone git@github.com:np-guard/vmware-analyzer.git
cd vmware-analyzer
make mod 
make build
```

Test your build by running `./bin/nsxanalyzer -h`.


## Build analyzer image

Use the following to build a docker image:

```commandline
make nsx-analyzer-image
```

Test your image build by running `docker run nsx-analyzer:latest -h`.

### Image build configuration

| Name              | Default value | Description |
| :---------------- | :-----------  | :---------- |
| IMAGE_REGISTRY    |   docker.io   | The registry address to which the images should be pushed. |
| NSX_ANALYZER_TAG  |   latest      | The image tag for nsx-analyzer image build. |
| NSX_ANALYZER_IMAGE|   nsx-analyzer| The image name for nsx-analyzer image build. |
