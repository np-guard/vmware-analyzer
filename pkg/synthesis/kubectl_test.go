package synthesis

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/np-guard/vmware-analyzer/pkg/logging"
	"github.com/np-guard/vmware-analyzer/pkg/model"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

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
	ctl := kubeCTL{}
	ctl.clean()
	ctl.addCmd("kubectl apply -f " + path.Join(k8sDir, "pods.yaml"))
	for i := range pods {
		ctl.exposePod(pods[i].Name)
	}
	ctl.addCmd("kubectl apply -f " + path.Join(k8sDir, "policies.yaml"))
	for i := range pods {
		ctl.waitPod(pods[i].Name)
	}
	return ctl.createCmdFile(fileName)
}

func createTestEvironmentFile(fileName string, rc *collector.ResourcesContainerModel) error {
	ctl := kubeCTL{}
	parser := model.NewNSXConfigParserFromResourcesContainer(rc)
	if err := parser.RunParser(); err != nil{
		return err
	}
	config := parser.GetConfig()
	for src, dsts := range config.Connectivity() {
		for dst, conn := range dsts {
			er := 0
			if conn.Conn.TCPUDPSet().IsEmpty() {
				er = 1
			}
			ctl.testPodsConnection(strings.ToLower(src.Name()), strings.ToLower(dst.Name()), er)
		}
	}
	return ctl.createCmdFile(fileName)
}

func createCleanEvironmentFile(fileName string, pods []*core.Pod) error {
	ctl := kubeCTL{}
	ctl.clean()
	for i := range pods {
		ctl.deletePod(pods[i].Name)
	}
	return ctl.createCmdFile(fileName)
}

func runK8STraceFlow(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runK8STraceFlow.log"))
	require.Nil(t, err)
	kubeDir := path.Join(synTest.debugDir(), "kube_test_dir")
	k8sDir := path.Join(kubeDir, k8sResourcesDir)
	setEvironmentFile := path.Join(kubeDir, "setEnvironment.sh")
	cleanEvironmentFile := path.Join(kubeDir, "cleanEnvironment.sh")
	testEvironmentFile := path.Join(kubeDir, "testEnvironment.sh")
	// create K8S k8sResources:
	k8sResources, err := NSXToK8sSynthesis(rc, synTest.options())
	require.Nil(t, err)
	fixPodsResources(k8sResources.pods)
	fixPoliciesResources(k8sResources.networkPolicies)
	
	require.Nil(t, k8sResources.CreateDir(kubeDir))
	require.Nil(t, createSetEvironmentFile(k8sDir, setEvironmentFile, k8sResources.pods))
	require.Nil(t, createTestEvironmentFile(testEvironmentFile, rc))
	require.Nil(t, createCleanEvironmentFile(cleanEvironmentFile, k8sResources.pods))
}

type kubeCTL struct {
	cmdLines []string
}

func (ctl *kubeCTL) addCmd(cmd string) {
	ctl.cmdLines = append(ctl.cmdLines, cmd)
}
func (ctl *kubeCTL) clean() {
	ctl.addCmd("kubectl delete networkpolicy --all")
	ctl.addCmd("kubectl delete service --all")
}

func (ctl *kubeCTL) exposePod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl expose pod %s --port=5001 --target-port=5000 --name \"%s-service\"", name, name))
}

func (ctl *kubeCTL) waitPod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl wait --timeout=3m --for=condition=Ready pod/%s", name))
}
func (ctl *kubeCTL) deletePod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl delete pod %s", name))
}
func (ctl *kubeCTL) testPodsConnection(from, to string, er int) {
	ctl.addCmd(fmt.Sprintf("kubectl exec %s -- wget -qO- --timeout=2 http://%s-service:5001/metrics", from, to))
	ctl.addCmd(fmt.Sprintf("echo Connection Test from %s to %s, exit status should be %d: exit status = $?", from, to, er))
}

func (ctl *kubeCTL) createCmdFile(fileName string) error {
	return common.WriteToFile(fileName, strings.Join(ctl.cmdLines, "\n"))
}

