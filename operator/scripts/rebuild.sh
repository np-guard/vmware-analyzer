# clean up cr instances
kubectl delete nsxmigration --all
# remove controller and crd
make undeploy
#validate undeploy
#kubectl api-resources | grep npguard
# rebuild 
make manifests
make docker-build docker-push
make deploy
#validate deploy
kubectl get pods -n operator-system
