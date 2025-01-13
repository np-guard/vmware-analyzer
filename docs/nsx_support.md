# NSX supported resources


### API Version

See [NSX REST API](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/).


### DFW supported fields

Features not yet supported:

* Category of type `Ethernet`
* Supported protocols: `TCP`, `UDP`, `ICMP`
* Rules fields `SourcesExcluded`, `DestinationsExcluded`
* Rules fields `DestinationGroups`, `SourceGroups` with  IP Addresses.



### Topology resources 

Following resources are considered for the analysis:
* VMs
* Segments 
* T1 Gateway
* T0 Gateway


### Endpoints 

The analysis endpoints are the VMs retrieved from `GET api/v1/fabric/virtual-machines`.


### More limitations and assumptions

* Currently IPv6 protocols and addresses are not supported. 
* Assuming single NSX domain.