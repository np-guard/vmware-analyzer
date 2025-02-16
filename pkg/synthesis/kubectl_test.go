package synthesis

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/common"
	"github.com/stretchr/testify/require"
)

func TestKubeCTL(t *testing.T) {
	ctl := kubeCTL{}
	ctl.clean()
	ctl.createPod("pod-a", []string{"group__ga=true"})
	ctl.createPod("pod-b", []string{"group__gb=true"})
	ctl.waitPod("pod-a")
	ctl.waitPod("pod-b")
	ctl.testPodsConnection("pod-a", "pod-b", 0)
	require.Nil(t, ctl.createDefaultDeny())
	ctl.testPodsConnection("pod-a", "pod-b", 1)
	require.Nil(t, ctl.createDNSPolicy())
	ctl.testPodsConnection("pod-a", "pod-b", 1)
	require.Nil(t, ctl.createAllowPolicy("pod-a", "pod-b","group__ga","group__gb",  false ))
	ctl.testPodsConnection("pod-a", "pod-b", 1)
	require.Nil(t, ctl.createAllowPolicy("pod-b", "pod-a","group__gb","group__ga",  true ))
	ctl.testPodsConnection("pod-a", "pod-b", 0)

	ctl.deletePod("pod-a")
	ctl.deletePod("pod-b")
	ctl.clean()
	require.Nil(t, ctl.createCmdFile())

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
	ctl.addCmd(fmt.Sprintf("kubectl expose pod %s --port=5001 --target-port=5000 --selector=\"%s\" --name \"%s-service\"", name, labelsStr, name))
	ctl.addCmd("sleep 3")
}

func (ctl *kubeCTL) waitPod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl wait --timeout=3m --for=condition=Ready pod/%s", name))
}
func (ctl *kubeCTL) deletePod(name string) {
	ctl.addCmd(fmt.Sprintf("kubectl delete pod %s", name))
}
func (ctl *kubeCTL) testPodsConnection(from, to string, er int) {
	ctl.addCmd(fmt.Sprintf("kubectl exec %s -- wget -qO- --timeout=2 http://%s-service:5001/metrics", from, to))
	ctl.addCmd(fmt.Sprintf("echo Connection Test $? == %d", er))
}

func (ctl *kubeCTL) createCmdFile() error {
	return common.WriteToFile(path.Join(getTestsDirActualOut(), "kube_tests", "cmd.sh"), strings.Join(ctl.cmdLines, "\n"))
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
