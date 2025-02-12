kubectl run new-vm-1 --image=ahmet/app-on-two-ports --labels="group__research-app=true,group__research-seg-1=true"
kubectl run new-vm-3  --image=ahmet/app-on-two-ports --labels="group__research-app=true,group__research-seg-1=true"
kubectl run new-vm-2  --image=ahmet/app-on-two-ports --labels="group__research-app=true"
kubectl run new-vm-4 --image=ahmet/app-on-two-ports --labels="group__research-app=true,group__research-seg-1=true"
kubectl run new-virtual-machine  --image=ahmet/app-on-two-ports --labels="group__research-app=true"

#  kubectl get pods --selector=group__research-app=true

# shell from pod container:
# kubectl exec --stdin --tty new-vm-1 -- sh

# check conn without sh:
# kubectl exec new-vm-1 -- wget -qO- --timeout=2 http://10.244.120.68:8000
#  kubectl exec new-vm-1 -- wget -qO- --timeout=2  http://192.168.110.130:5000/metrics

# https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/09-allow-traffic-only-to-a-port.md
