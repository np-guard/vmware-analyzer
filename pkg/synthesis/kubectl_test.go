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
)


func runK8STraceFlow(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runK8STraceFlow.log"))
	require.Nil(t, err)
	kubeDir := path.Join(synTest.debugDir(), "kube_test_dir")
	k8sDir := path.Join(kubeDir, k8sResourcesDir)
	setEvironmentFile := path.Join(kubeDir, "setEnvironment.sh")
	cleanEvironmentFile := path.Join(kubeDir, "cleanEnvironment.sh")
	// create K8S k8sResources:
	k8sResources, err := NSXToK8sSynthesis(rc,nil, synTest.options())
	require.Nil(t, err)
	fixPodsResources(k8sResources.pods)
	fixPoliciesResources(k8sResources.networkPolicies)

	require.Nil(t, k8sResources.CreateDir(kubeDir))
	require.Nil(t, createSetEvironmentFile(k8sDir, setEvironmentFile, k8sResources.pods))
	require.Nil(t, createCleanEvironmentFile(cleanEvironmentFile, k8sResources.pods))
	require.Nil(t, runCmdFile(setEvironmentFile))
	require.Nil(t, k8sAnalyzer(k8sDir, path.Join(kubeDir, "k8s_connectivity.txt"), "txt"))
	require.Nil(t, runTests(kubeDir, rc))
	require.Nil(t, runCmdFile(cleanEvironmentFile))

}

func fixPodsResources(pods []*core.Pod) {
	for i := range pods {
		name := strings.ToLower(pods[i].Name)
		pods[i].Spec.Containers = []core.Container{{Name: "app-on-two-ports", Image: "ahmet/app-on-two-ports"}}
		pods[i].Name = name
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

func createSetEvironmentFile(k8sDir, fileName string, pods []*core.Pod) error {
	ctl := cubeCLI{}
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

func runTests(kubeDir string, rc *collector.ResourcesContainerModel) error {
	connTestFile := path.Join(kubeDir, "connTest.sh")
	connReportFile := path.Join(kubeDir, "connTestReport.txt")
	errorLines := []string{}
	reportLines := []string{}
	ctl := cubeCLI{}
	ctl.testPodsConnection()
	ctl.createCmdFile(connTestFile)
	parser := analyzer.NewNSXConfigParserFromResourcesContainer(rc)
	if err := parser.RunParser(); err != nil {
		return err
	}
	parser.GetConfig().ComputeConnectivity(nil)
	for src, dsts := range parser.GetConfig().AnalyzedConnectivity() {
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

func createCleanEvironmentFile(fileName string, pods []*core.Pod) error {
	ctl := cubeCLI{}
	ctl.clean()
	for i := range pods {
		ctl.deletePod(pods[i].Name)
	}
	return ctl.createCmdFile(fileName)
}

/////////////////////////////////////////////////////////////////////////////////////////////
type cubeCLI struct {
	cmdLines []string
}
func (cli *cubeCLI) addCmd(cmd string) {
	cli.cmdLines = append(cli.cmdLines, cmd)
}
func (cli *cubeCLI) clean() {
	cli.addCmd("kubectl delete networkpolicy --all")
	cli.addCmd("kubectl delete service --all")
}
func (cli *cubeCLI) exposePod(name string) {
	cli.addCmd(fmt.Sprintf("kubectl expose pod %s --port=5001 --target-port=5000 --name \"%s-service\"", name, name))
}
func (cli *cubeCLI) waitPod(name string) {
	cli.addCmd(fmt.Sprintf("kubectl wait --timeout=3m --for=condition=Ready pod/%s", name))
}
func (cli *cubeCLI) applyResourceFile(resourceFile string){
	cli.addCmd("kubectl apply -f " + resourceFile)
}
func (cli *cubeCLI) deletePod(name string) {
	cli.addCmd(fmt.Sprintf("kubectl delete pod %s", name))
}
func (cli *cubeCLI) testPodsConnection() {
	cli.addCmd("kubectl exec ${1} -- wget -qO- --timeout=2 http://${2}-service:5001/metrics")
	cli.addCmd("exit $?")
}
func (cli *cubeCLI) createCmdFile(fileName string) error {
	return common.WriteToFile(fileName, strings.Join(cli.cmdLines, "\n"))
}
func runCmdFile(fileName string, arg ...string) error{
	return exec.Command("bash", append([]string{fileName}, arg...)...).Run()	
}