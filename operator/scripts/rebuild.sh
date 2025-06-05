# clean up cr instances
kubectl delete nsxmigration --all
#kubectl delete netpol --all
kubectl delete secret my-nsx
# remove controller and crd
make undeploy
#validate undeploy
#kubectl api-resources | grep npguard
# rebuild 
make manifests
make docker-build docker-push
make deploy
kubectl apply -f operator-deployment.yaml
#validate deploy
kubectl get pods -n operator-system
kubectl create secret generic my-nsx  --from-literal=username=$NSX_USER --from-literal=password=$NSX_PASSWORD --from-literal=url=$NSX_HOST --from-literal=insecureSkipVerify=true

# kubectl apply -f config/samples/nsx_v1alpha1_nsxmigration_3.yaml
