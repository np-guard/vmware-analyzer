package synthesis

import (
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	admin "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/vmware-analyzer/internal/common"
	analyzer "github.com/np-guard/vmware-analyzer/pkg/analyzer"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/resources"
	"github.com/np-guard/vmware-analyzer/pkg/synthesis/ocpvirt/utils"
)

// This test is creating pods and policies and check the connections, using kubectl API.
// The pods are created with a container that listen to TCP port 5000
// The test is adjusted to this container:
//  1. all TCP ports at the netpols are changed to tcp:5000
//  2. connection between two pods is allowed iff the analyzed connection contains TCP
//
// At the end of the tests, services, pods and policies are deleted,
// if you wish not to delete the pods pods, to save time to the next test run, set this flag to false:
const deletePodsAtCleanup = true

func runK8STraceFlow(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	if !hasKubectl() {
		return
	}
	kubeDir := path.Join(synTest.debugDir(), "kube_test_dir")
	err := logging.Tee(path.Join(kubeDir, "runK8STraceFlow.log"))
	require.Nil(t, err)
	k8sDir := path.Join(kubeDir, resources.K8sResourcesDir)
	setEnvironmentFile := path.Join(kubeDir, "setEnvironment.sh")
	cleanEnvironmentFile := path.Join(kubeDir, "cleanEnvironment.sh")
	// create K8S k8sResources
	k8sResources, err := ocpvirt.NSXToK8sSynthesis(rc, nil, synTest.options())
	require.Nil(t, err)
	// adjust k8sResources for the tests:
	fixPodsResources(synTest.name, k8sResources.Pods)
	fixPoliciesResources(k8sResources.NetworkPolicies)
	fixAdminPoliciesResources(k8sResources.AdminNetworkPolicies)
	require.Nil(t, k8sResources.WriteResourcesToDir(kubeDir))
	// run netpol-analyzer, for debugging:
	_, err = utils.K8sAnalyzer(k8sDir, path.Join(kubeDir, "k8s_connectivity.txt"), "txt")
	require.Nil(t, err)

	// create the kubectl bash files:
	require.Nil(t, createSetEnvironmentFile(k8sDir, setEnvironmentFile, k8sResources.Pods))
	require.Nil(t, createCleanEnvironmentFile(cleanEnvironmentFile, k8sResources.Pods))

	// create environment:
	logging.Debugf("creating environment from file %s", setEnvironmentFile)
	require.Nil(t, runCmdFile(setEnvironmentFile))
	logging.Debug("environment created")

	// check connections:
	checkErr := testConnections(synTest, kubeDir, rc)
	// clean environment - services and policies are deleted
	// we must clean before we checks for errors:
	cleanErr := runCmdFile(cleanEnvironmentFile)
	require.Nil(t, checkErr)
	require.Nil(t, cleanErr)
}

// /////////////////////////////////////////////////////////////////////
func podTestName(testName, vmName string) string {
	return strings.ReplaceAll(strings.ToLower(fmt.Sprintf("%s-%s", testName, vmName)), " ", "-")
}

func fixPodsResources(testName string, pods []*core.Pod) {
	for i := range pods {
		pods[i].Spec.Containers = []core.Container{{Name: "app-on-two-ports", Image: "ahmet/app-on-two-ports"}}
		pods[i].Name = podTestName(testName, pods[i].Name)
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
		port.PortNumber = &admin.Port{Protocol: core.ProtocolTCP, Port: 5000}
		port.PortRange = nil
	}
}

// ///////////////////////////////////////////////////////////////////////////////////////
func createSetEnvironmentFile(k8sDir, fileName string, pods []*core.Pod) error {
	ctl := kubectlFile{}
	ctl.clean()
	podsExist, err := checkPodsExist(k8sDir, pods)
	if err != nil {
		return err
	}
	if !podsExist {
		// to save time, we create the pods only if it is not exist:
		ctl.applyResourceFile(path.Join(k8sDir, "pods.yaml"))
	}
	for i := range pods {
		ctl.exposePod(pods[i].Name)
	}
	ctl.applyResourceFile(path.Join(k8sDir, "policies.yaml"))
	ctl.applyResourceFile(path.Join(k8sDir, "adminPolicies.yaml"))
	for i := range pods {
		ctl.waitPod(pods[i].Name)
	}
	return ctl.createCmdFile(fileName)
}

func checkPodsExist(kubeDir string, pods []*core.Pod) (bool, error) {
	testFile := path.Join(kubeDir, "checkPods.sh")
	names := common.CustomStrSliceToStrings(pods, func(pod *core.Pod) string { return pod.Name })
	ctl := kubectlFile{}
	ctl.testPodsExist(names)
	if err := ctl.createCmdFile(testFile); err != nil {
		return false, err
	}
	return runCmdFile(testFile) == nil, nil
}

func createCleanEnvironmentFile(fileName string, pods []*core.Pod) error {
	ctl := kubectlFile{}
	ctl.clean()
	if deletePodsAtCleanup {
		for _, pod := range pods {
			ctl.deletePod(pod.Name)
		}
	}
	return ctl.createCmdFile(fileName)
}

// ///////////////////////////////////////////////////////////////
func testConnections(test *synthesisTest, kubeDir string, rc *collector.ResourcesContainerModel) error {
	connTestFile := path.Join(kubeDir, "connTest.sh")
	connReportFile := path.Join(kubeDir, "connTestReport.txt")
	// create one bash file for all tests:
	err := createConnTestFile(connTestFile)
	if err != nil {
		return err
	}
	// get analyzed connectivity:
	_, connMap, _, err := analyzer.NSXConnectivityFromResourcesContainer(rc, test.outputParams())
	if err != nil {
		return err
	}
	// iterate over the connMap, create test for each connection:
	tests := []*connTest{}
	for src, dsts := range connMap {
		for dst, conn := range dsts {
			test := &connTest{
				connTestFile: connTestFile,
				src:          podTestName(test.name, src.Name()),
				dst:          podTestName(test.name, dst.Name()),
				allowed:      !conn.Conn.Intersect(netset.AllTCPTransport()).IsEmpty(),
			}
			tests = append(tests, test)
		}
	}
	// run the tests, concurently, to save time:
	var wg sync.WaitGroup
	for _, test := range tests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			test.run()
		}()
	}
	wg.Wait()

	// summarize the result into a file:
	nConnected := common.SliceCountFunc(tests, func(t *connTest) bool { return !t.connectResult })
	logging.Debugf("checked %d connections, %d succeed to connect, see file %s for details", len(tests), nConnected, connReportFile)
	err = common.WriteToFile(connReportFile, common.JoinStringifiedSlice(tests, "\n"))
	nErrors := common.SliceCountFunc(tests, func(t *connTest) bool { return !t.ok() })
	if nErrors > 0 {
		errorLine := fmt.Sprintf("found %d connections missmatches, see file %s for details", nErrors, connReportFile)
		return errors.New(errorLine)
	}
	return err
}

func createConnTestFile(connTestFile string) error {
	ctl := kubectlFile{}
	ctl.testPodsConnection()
	return ctl.createCmdFile(connTestFile)
}

// ////////////////////////////////////////////////////////////////////////////////////////
// a struct repersent one connction:
type connTest struct {
	connTestFile  string // the bash file to test with
	allowed       bool   // is the connection allowed by analysis
	connectResult bool   // doed kubectl succeed to connect
	src, dst      string
}

func (test *connTest) String() string {
	miss := ""
	if !test.ok() {
		miss = "MISSMATCH: "
	}
	return fmt.Sprintf("%s%s -> %s connected:%t allowed:%t", miss, test.src, test.dst, test.connectResult, test.allowed)
}
func (test *connTest) ok() bool {
	return test.connectResult == test.allowed
}
func (test *connTest) run() {
	err := runCmdFile(test.connTestFile, test.src, test.dst)
	test.connectResult = err == nil
	if !test.ok() {
		logging.Warn(test.String())
	}
}

// ///////////////////////////////////////////////////////////////////////////////////////////
// interface to create bash files with kubectl commands to run:
type kubectlFile struct {
	cmdLines []string
}

func (ctl *kubectlFile) addCmd(cmd string) {
	ctl.cmdLines = append(ctl.cmdLines, cmd)
}
func (ctl *kubectlFile) clean() {
	ctl.addCmd("kubectl delete networkpolicy --all")
	ctl.addCmd("kubectl delete adminnetworkpolicies --all")
	ctl.addCmd("kubectl delete service --all")
}
func (ctl *kubectlFile) exposePod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl expose pod %s --port=5001 --target-port=5000 --name \"%s-service\"", name, name))
}
func (ctl *kubectlFile) waitPod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl wait --timeout=3m --for=condition=Ready pod/%s", name))
}
func (ctl *kubectlFile) deletePod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl delete pod %s", name))
}
func (ctl *kubectlFile) applyResourceFile(resourceFile string) {
	ctl.addCmd("kubectl apply -f " + resourceFile)
}
func (ctl *kubectlFile) testPodsConnection() {
	ctl.addCmd("kubectl exec ${1} -- wget -qO- --timeout=2 http://${2}-service:5001/metrics")
	ctl.addCmd("exit $?")
}
func (ctl *kubectlFile) testPodsExist(names []string) {
	ctl.addCmd("kubectl get pods " + strings.Join(names, " "))
	ctl.addCmd("exit $?")
}
func (ctl *kubectlFile) createCmdFile(fileName string) error {
	return common.WriteToFile(fileName, strings.Join(ctl.cmdLines, "\n"))
}

// ////////////////////////////////////////////////////////////////////////
func runCmdFile(fileName string, arg ...string) error {
	//nolint:gosec //its a safe run
	return exec.Command("bash", append([]string{fileName}, arg...)...).Run()
}
func hasKubectl() bool {
	return exec.Command("kubectl", "get", "pods").Run() == nil
}
