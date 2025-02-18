 kubectl create configmap demo-configmap --from-file=netpol.json

 kubectl get configmap demo-configmap -o yaml | less
