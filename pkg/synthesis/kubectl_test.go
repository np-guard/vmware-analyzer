package synthesis

import (
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"testing"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vmware-analyzer/internal/common"
	analyzer "github.com/np-guard/vmware-analyzer/pkg/analyzer"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

func runK8STraceFlow(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	if !hasKubectlExec() {
		return
	}
	kubeDir := path.Join(synTest.debugDir(), "kube_test_dir")
	err := logging.Tee(path.Join(kubeDir, "runK8STraceFlow.log"))
	require.Nil(t, err)
	k8sDir := path.Join(kubeDir, k8sResourcesDir)
	setEvironmentFile := path.Join(kubeDir, "setEnvironment.sh")
	cleanEvironmentFile := path.Join(kubeDir, "cleanEnvironment.sh")
	// create K8S k8sResources, and adjust them for the tests:
	k8sResources, err := NSXToK8sSynthesis(rc, nil, synTest.options())
	require.Nil(t, err)
	fixPodsResources(k8sResources.pods)
	fixPoliciesResources(k8sResources.networkPolicies)
	// fixAdminPoliciesResources(k8sResources.adminNetworkPolicies)
	require.Nil(t, k8sResources.CreateDir(kubeDir))
	// require.Nil(t, k8sAnalyzer(k8sDir, path.Join(kubeDir, "k8s_connectivity.txt"), "txt"))

	// create the kubectl files:
	require.Nil(t, createSetEvironmentFile(k8sDir, setEvironmentFile, k8sResources.pods))
	require.Nil(t, createCleanEvironmentFile(cleanEvironmentFile, k8sResources.pods))

	// crreate environment:
	require.Nil(t, runCmdFile(setEvironmentFile))
	logging.Debugf("environment created from file %s", setEvironmentFile)

	// check connections:
	checkErr := testConnections(kubeDir, rc)
	// clean environmaent, we must clean before we checks for errors:
	cleanErr := runCmdFile(cleanEvironmentFile)
	require.Nil(t, checkErr)
	require.Nil(t, cleanErr)

}

// /////////////////////////////////////////////////////////////////////
func fixPodsResources(pods []*core.Pod) {
	for i := range pods {
		pods[i].Spec.Containers = []core.Container{{Name: "app-on-two-ports", Image: "ahmet/app-on-two-ports"}}
		pods[i].Name = strings.ToLower(pods[i].Name)
	}
}

func fixPoliciesResources(networkPolicies []*networking.NetworkPolicy) {
	port := intstr.FromInt(5000)
	for in := range networkPolicies {
		for ie := range networkPolicies[in].Spec.Egress {
			for ip := range networkPolicies[in].Spec.Egress[ie].Ports {
				if *networkPolicies[in].Spec.Egress[ie].Ports[ip].Protocol == core.ProtocolTCP {
					networkPolicies[in].Spec.Egress[ie].Ports[ip].Port = &port
				}
			}
		}
		for ie := range networkPolicies[in].Spec.Ingress {
			for ip := range networkPolicies[in].Spec.Ingress[ie].Ports {
				if *networkPolicies[in].Spec.Ingress[ie].Ports[ip].Protocol == core.ProtocolTCP {
					networkPolicies[in].Spec.Ingress[ie].Ports[ip].Port = &port
				}
			}
		}
	}
}

func fixAdminPoliciesResources(adminNetworkPolicies []*admin.AdminNetworkPolicy) {
	for in := range adminNetworkPolicies {
		for ie := range adminNetworkPolicies[in].Spec.Egress {
			for ip := range *adminNetworkPolicies[in].Spec.Egress[ie].Ports {
				fixAdminPort(&(*adminNetworkPolicies[in].Spec.Egress[ie].Ports)[ip])
			}
		}
		for ie := range adminNetworkPolicies[in].Spec.Ingress {
			for ip := range *adminNetworkPolicies[in].Spec.Ingress[ie].Ports {
				fixAdminPort(&(*adminNetworkPolicies[in].Spec.Ingress[ie].Ports)[ip])
			}
		}
	}
}
func fixAdminPort(port *admin.AdminNetworkPolicyPort) {
	if port.PortNumber != nil && port.PortNumber.Protocol == core.ProtocolTCP ||
		port.PortRange != nil && port.PortRange.Protocol == core.ProtocolTCP {
		port.PortNumber = &admin.Port{ Protocol: core.ProtocolTCP, Port: 5000}
		port.PortRange = nil
	}
}

// ///////////////////////////////////////////////////////////////////////////////////////
func createSetEvironmentFile(k8sDir, fileName string, pods []*core.Pod) error {
	ctl := kubeCTLFile{}
	ctl.clean()
	ctl.applyResourceFile(path.Join(k8sDir, "pods.yaml"))
	for i := range pods {
		ctl.exposePod(pods[i].Name)
	}
	ctl.applyResourceFile(path.Join(k8sDir, "policies.yaml"))
	for i := range pods {
		ctl.waitPod(pods[i].Name)
	}
	return ctl.createCmdFile(fileName)
}

func createCleanEvironmentFile(fileName string, pods []*core.Pod) error {
	ctl := kubeCTLFile{}
	ctl.clean()
	for i := range pods {
		ctl.deletePod(pods[i].Name)
	}
	return ctl.createCmdFile(fileName)
}

// ////////////////////////////////////////////////////////////////////////////////////////
func testConnections(kubeDir string, rc *collector.ResourcesContainerModel) error {
	connTestFile := path.Join(kubeDir, "connTest.sh")
	connReportFile := path.Join(kubeDir, "connTestReport.txt")
	errorLines := []string{}
	reportLines := []string{}
	// create test generic file:
	ctl := kubeCTLFile{}
	ctl.testPodsConnection()
	ctl.createCmdFile(connTestFile)
	// get analized connectivity:
	parser := analyzer.NewNSXConfigParserFromResourcesContainer(rc)
	if err := parser.RunParser(); err != nil {
		return err
	}
	parser.GetConfig().ComputeConnectivity(nil)
	connMap := parser.GetConfig().AnalyzedConnectivity()
	// iterate over the connections, test each connection:
	for src, dsts := range connMap {
		for dst, conn := range dsts {
			err := runCmdFile(connTestFile, strings.ToLower(src.Name()), strings.ToLower(dst.Name()))
			allow := !conn.Conn.Intersect(netset.AllTCPTransport()).IsEmpty()
			connected := err == nil
			reportLine := fmt.Sprintf("%s -> %s connected:%t allowed:%t", src.Name(), dst.Name(), connected, allow)
			reportLines = append(reportLines, reportLine)
			if allow != connected {
				logging.Warn(reportLine)
				errorLines = append(errorLines, reportLine)
			}
		}
	}
	// summarize the result:
	logging.Debugf("checked %d connections, see file %s for details", len(reportLines), connReportFile)
	reportLines = append(reportLines, "Errors:")
	reportLines = append(reportLines, errorLines...)
	err := common.WriteToFile(connReportFile, strings.Join(reportLines, "\n"))
	if len(errorLines) > 0 {
		if err != nil {
			return err
		}
		errorLine := fmt.Sprintf("found %d connections missmatches, see file %s for details", len(errorLines), connReportFile)
		return errors.New(errorLine)
	}
	return nil
}

// ///////////////////////////////////////////////////////////////////////////////////////////
// interface to create bash files with kubectl commands to run:
type kubeCTLFile struct {
	cmdLines []string
}

func (ctl *kubeCTLFile) addCmd(cmd string) {
	ctl.cmdLines = append(ctl.cmdLines, cmd)
}
func (ctl *kubeCTLFile) clean() {
	ctl.addCmd("kubectl delete networkpolicy --all")
	ctl.addCmd("kubectl delete adminnetworkpolicies --all")
	ctl.addCmd("kubectl delete service --all")

}
func (ctl *kubeCTLFile) exposePod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl expose pod %s --port=5001 --target-port=5000 --name \"%s-service\"", name, name))
}
func (ctl *kubeCTLFile) waitPod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl wait --timeout=3m --for=condition=Ready pod/%s", name))
}
func (ctl *kubeCTLFile) applyResourceFile(resourceFile string) {
	ctl.addCmd("kubectl apply -f " + resourceFile)
}
func (ctl *kubeCTLFile) deletePod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl delete pod %s", name))
}
func (ctl *kubeCTLFile) testPodsConnection() {
	ctl.addCmd("kubectl exec ${1} -- wget -qO- --timeout=2 http://${2}-service:5001/metrics")
	ctl.addCmd("exit $?")
}
func (ctl *kubeCTLFile) createCmdFile(fileName string) error {
	return common.WriteToFile(fileName, strings.Join(ctl.cmdLines, "\n"))
}

// ////////////////////////////////////////////////////////////////////////
func runCmdFile(fileName string, arg ...string) error {
	return exec.Command("bash", append([]string{fileName}, arg...)...).Run()
}
func hasKubectlExec() bool {
	_, err := exec.LookPath("kubectl")
	return err == nil
}
