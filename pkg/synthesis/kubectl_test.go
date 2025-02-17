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
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestKubeCTL(t *testing.T) {
	ctl := kubeCTL{}
	ctl.clean()
	ctl.createPod("pod-a", []string{"group__ga=true"})
	ctl.createPod("pod-b", []string{"group__gb=true"})
	ctl.waitPod("pod-a")
	ctl.waitPod("pod-b")
	ctl.testPodsConnection("pod-a", "pod-b", 1)
	ctl.exposePod("pod-b")
	ctl.testPodsConnection("pod-a", "pod-b", 0)
	require.Nil(t, ctl.createDefaultDeny())
	ctl.testPodsConnection("pod-a", "pod-b", 1)
	require.Nil(t, ctl.createDNSPolicy())
	ctl.testPodsConnection("pod-a", "pod-b", 1)
	require.Nil(t, ctl.createAllowPolicy("pod-a", "pod-b", "group__ga", "group__gb", false))
	ctl.testPodsConnection("pod-a", "pod-b", 1)
	require.Nil(t, ctl.createAllowPolicy("pod-b", "pod-a", "group__gb", "group__ga", true))
	ctl.testPodsConnection("pod-a", "pod-b", 0)

	ctl.deletePod("pod-a")
	ctl.deletePod("pod-b")
	ctl.clean()
	require.Nil(t, ctl.createCmdFile(path.Join(getTestsDirActualOut(), "kube_tests", "cmd.sh")))

}

func runK8STraceFlow(synTest *synthesisTest, t *testing.T, rc *collector.ResourcesContainerModel) {
	err := logging.Tee(path.Join(synTest.debugDir(), "runK8STraceFlow.log"))
	require.Nil(t, err)
	kubeDir := path.Join(synTest.debugDir(), "kube_test_dir")
	k8sDir := path.Join(kubeDir, k8sResourcesDir)
	// create K8S resources:
	resources, err := NSXToK8sSynthesis(rc, synTest.options())
	require.Nil(t, err)
	for i := range resources.pods {
		name := strings.ToLower(resources.pods[i].Name)
		resources.pods[i].Spec.Containers = []core.Container{{Name: "app-on-two-ports", Image: "ahmet/app-on-two-ports"}}
		resources.pods[i].Name = name
	}
	port := intstr.FromInt(5000)
	for in := range resources.networkPolicies {
		for ie := range resources.networkPolicies[in].Spec.Egress {
			for ip := range resources.networkPolicies[in].Spec.Egress[ie].Ports {
				if *resources.networkPolicies[in].Spec.Egress[ie].Ports[ip].Protocol == core.ProtocolTCP {
					resources.networkPolicies[in].Spec.Egress[ie].Ports[ip].Port = &port
				}
			}
		}
		for ie := range resources.networkPolicies[in].Spec.Ingress {
			for ip := range resources.networkPolicies[in].Spec.Ingress[ie].Ports {
				if *resources.networkPolicies[in].Spec.Ingress[ie].Ports[ip].Protocol == core.ProtocolTCP {
					resources.networkPolicies[in].Spec.Ingress[ie].Ports[ip].Port = &port
				}
			}
		}
	}
	err = resources.CreateDir(kubeDir)
	require.Nil(t, err)

	ctl := kubeCTL{}
	ctl.clean()
	ctl.addCmd("kubectl apply -f " + path.Join(k8sDir, "pods.yaml"))
	for i := range resources.pods {
		ctl.exposePod(resources.pods[i].Name)
	}
	ctl.addCmd("kubectl apply -f " + path.Join(k8sDir, "policies.yaml"))
	for i := range resources.pods {
		ctl.waitPod(resources.pods[i].Name)
	}

	// get the config:
	parser := model.NewNSXConfigParserFromResourcesContainer(rc)
	err = parser.RunParser()
	require.Nil(t, err)
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

	for i := range resources.pods {
		ctl.deletePod(resources.pods[i].Name)
	}
	require.Nil(t, ctl.createCmdFile(path.Join(kubeDir, "cmd.sh")))
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

func (ctl *kubeCTL) createPod(name string, labels []string) {
	labelsStr := strings.Join(labels, ",")
	ctl.addCmd(fmt.Sprintf("kubectl run %s --image=ahmet/app-on-two-ports --labels=\"%s\"", name, labelsStr))
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

func (ctl *kubeCTL) createDefaultDeny() error {
	err := common.WriteToFile(path.Join(getTestsDirActualOut(), "kube_tests", "defaultDeny.yaml"), strings.Join(defaultDeny, "\n"))
	ctl.addCmd("kubectl apply -f  defaultDeny.yaml")
	ctl.addCmd("sleep 3")
	return err
}
func (ctl *kubeCTL) createDNSPolicy() error {
	err := common.WriteToFile(path.Join(getTestsDirActualOut(), "kube_tests", "dnsPolicy.yaml"), strings.Join(dnsPolicy, "\n"))
	ctl.addCmd("kubectl apply -f  dnsPolicy.yaml")
	ctl.addCmd("sleep 3")
	return err
}

func (ctl *kubeCTL) createAllowPolicy(pod, policy string, podLabels, policyLabels string, ingress bool) error {
	boolToName := map[bool]string{false: "egress", true: "ingress"}
	boolToDir := map[bool]string{false: "to", true: "from"}
	name := fmt.Sprintf("%s-%s-%s", pod, boolToName[ingress], policy)
	fileName := name + ".yaml"
	str := fmt.Sprintf(strings.Join(allowPolicy, "\n"), name, podLabels, boolToName[ingress], boolToDir[ingress], policyLabels)
	err := common.WriteToFile(path.Join(getTestsDirActualOut(), "kube_tests", fileName), str)
	ctl.addCmd("kubectl apply -f " + fileName)
	ctl.addCmd("sleep 3")
	return err
}

var defaultDeny = []string{
	"apiVersion: networking.k8s.io/v1 ",
	"kind: NetworkPolicy",
	"metadata:",
	"    annotations:",
	"    creationTimestamp: null",
	"    name: default-deny",
	"    namespace: default",
	"spec:",
	"    podSelector: {}",
	"    policyTypes:",
	"        - Ingress",
	"        - Egress",
}

var dnsPolicy = []string{
	"apiVersion: networking.k8s.io/v1",
	"kind: NetworkPolicy",
	"metadata:",
	"  name: allow-dns-access",
	"  namespace: default",
	"spec:",
	"  podSelector:",
	"    matchLabels: {}",
	"  policyTypes:",
	"  - Egress",
	"  egress:",
	"  - to:",
	"    - namespaceSelector: {}",
	"      podSelector:",
	"        matchLabels:",
	"          k8s-app: kube-dns",
	"    ports:",
	"    - protocol: UDP",
	"      port: 53",
}

var allowPolicy = []string{
	"kind: NetworkPolicy",
	"apiVersion: networking.k8s.io/v1",
	"metadata:",
	"  name: api-allow-%s",
	"  namespace: default",
	"spec:",
	"  podSelector:",
	"    matchLabels:",
	"      %s: \"true\"",
	"  %s:",
	"  - ports:",
	"    - port: 5000",
	"    %s:",
	"    - podSelector:",
	"        matchLabels:",
	"          %s: \"true\"",
}
