/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"strconv"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	nsxv1alpha1 "github.com/np-guard/vmware-analyzer-operator/api/v1alpha1"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/runner"
)

//const migratensxFinalizer = "nsx.npguard.io/finalizer"

// Definitions to manage status conditions
const (
	// typeAvailableNSXMigration represents the status of the Deployment reconciliation
	typeAvailableNSXMigration = "Available"
	// typeDegradedNSXMigration represents the status used when the custom resource is deleted and the finalizer operations are yet to occur.
	//typeDegradedNSXMigration = "Degraded"
)

// NSXMigrationReconciler reconciles a NSXMigration object
type NSXMigrationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// The recorder will be used within the reconcile method of the controller to emit events
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=nsx.npguard.io,resources=nsxmigrations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nsx.npguard.io,resources=nsxmigrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=nsx.npguard.io,resources=nsxmigrations/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the NSXMigration object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *NSXMigrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("begin NSXMigrationReconciler Reconcile()")

	// Fetch the Memcached instance
	// The purpose is check if the Custom Resource for the Kind Memcached
	// is applied on the cluster if not we return nil to stop the reconciliation
	migratensx := &nsxv1alpha1.NSXMigration{}
	err := r.Get(ctx, req.NamespacedName, migratensx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the custom resource is not found then it usually means that it was deleted or not created
			// In this way, we will stop the reconciliation
			log.Info("migratensx resource not found. Ignoring since object must be deleted")
			// stop the Reconcile
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get migratensx")
		return ctrl.Result{}, err
	}

	// Let's just set the status as Unknown when no status is available
	/*if len(migratensx.Status.Conditions) == 0 {
		meta.SetStatusCondition(&migratensx.Status.Conditions, metav1.Condition{Type: typeAvailableNSXMigration, Status: metav1.ConditionUnknown, Reason: "Reconciling", Message: "Starting reconciliation"})
		if err = r.Status().Update(ctx, migratensx); err != nil {
			log.Error(err, "Failed to update migratensx status")
			return ctrl.Result{}, err
		}

		// Let's re-fetch the migratensx Custom Resource after updating the status
		// so that we have the latest state of the resource on the cluster and we will avoid
		// raising the error "the object has been modified, please apply
		// your changes to the latest version and try again" which would re-trigger the reconciliation
		// if we try to update it again in the following operations
		if err := r.Get(ctx, req.NamespacedName, migratensx); err != nil {
			log.Error(err, "Failed to re-fetch migratensx")
			return ctrl.Result{}, err
		}
	}*/

	// Let's add a finalizer. Then, we can define some operations which should
	// occur before the custom resource is deleted.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers
	/*if !controllerutil.ContainsFinalizer(migratensx, migratensxFinalizer) {
		log.Info("Adding Finalizer for NSXMigration")
		if ok := controllerutil.AddFinalizer(migratensx, migratensxFinalizer); !ok {
			log.Error(err, "Failed to add finalizer into the custom resource")
			return ctrl.Result{Requeue: true}, nil
		}

		if err = r.Update(ctx, migratensx); err != nil {
			log.Error(err, "Failed to update custom resource to add finalizer")
			return ctrl.Result{}, err
		}
	}*/

	// Check if the MigrateNSX instance is marked to be deleted, which is
	// indicated by the deletion timestamp being set.
	isMigrateNSXMarkedToBeDeleted := migratensx.GetDeletionTimestamp() != nil
	if isMigrateNSXMarkedToBeDeleted {
		log.Info("the MigrateNSX instance is marked to be deleted")
		/*if controllerutil.ContainsFinalizer(migratensx, migratensxFinalizer) {
			log.Info("Performing Finalizer Operations for MigrateNSX before delete CR")

			// Let's add here a status "Downgrade" to reflect that this resource began its process to be terminated.
			meta.SetStatusCondition(&migratensx.Status.Conditions, metav1.Condition{Type: typeDegradedNSXMigration,
				Status: metav1.ConditionUnknown, Reason: "Finalizing",
				Message: fmt.Sprintf("Performing finalizer operations for the custom resource: %s ", migratensx.Name)})

			if err := r.Status().Update(ctx, migratensx); err != nil {
				log.Error(err, "Failed to update Memcached status")
				return ctrl.Result{}, err
			}

			// Perform all operations required before removing the finalizer and allow
			// the Kubernetes API to remove the custom resource.
			r.doFinalizerOperationsForMigrateNSX(migratensx)

			// TODO(user): If you add operations to the doFinalizerOperationsForMigrateNSX method
			// then you need to ensure that all worked fine before deleting and updating the Downgrade status
			// otherwise, you should requeue here.

			// Re-fetch the migratensx Custom Resource before updating the status
			// so that we have the latest state of the resource on the cluster and we will avoid
			// raising the error "the object has been modified, please apply
			// your changes to the latest version and try again" which would re-trigger the reconciliation
			if err := r.Get(ctx, req.NamespacedName, migratensx); err != nil {
				log.Error(err, "Failed to re-fetch migratensx")
				return ctrl.Result{}, err
			}

			meta.SetStatusCondition(&migratensx.Status.Conditions, metav1.Condition{Type: typeDegradedNSXMigration,
				Status: metav1.ConditionTrue, Reason: "Finalizing",
				Message: fmt.Sprintf("Finalizer operations for custom resource %s name were successfully accomplished", migratensx.Name)})

			if err := r.Status().Update(ctx, migratensx); err != nil {
				log.Error(err, "Failed to update Memcached status")
				return ctrl.Result{}, err
			}

			log.Info("Removing Finalizer for MigrateNSX after successfully perform the operations")
			if ok := controllerutil.RemoveFinalizer(migratensx, migratensxFinalizer); !ok {
				log.Error(err, "Failed to remove finalizer for Memcached")
				return ctrl.Result{Requeue: true}, nil
			}

			if err := r.Update(ctx, migratensx); err != nil {
				log.Error(err, "Failed to remove finalizer for Memcached")
				return ctrl.Result{}, err
			}

		}*/
		// stop the Reconcile
		return ctrl.Result{}, nil
	}

	if meta.IsStatusConditionTrue(migratensx.Status.Conditions, typeAvailableNSXMigration) {
		// migration completed successfully - no need to re-run...
		// (currently reconcile is triggered  by status update after success )
		log.Info("exit Reconcile without error - no need to call nsxMigration() because status Available true is already set")
		// stop the Reconcile
		return ctrl.Result{}, nil
	}

	// MigrateNSX instance should trigger nsxMigration() [on create/update action]
	// TODO: add migration logic here ...
	if err := r.nsxMigration(migratensx, ctx, log); err != nil {
		log.Error(err, "Failed to run nsxMigration")

		// The following implementation will update the status
		meta.SetStatusCondition(&migratensx.Status.Conditions, metav1.Condition{Type: typeAvailableNSXMigration,
			Status: metav1.ConditionFalse, Reason: "Reconciling",
			Message: fmt.Sprintf("Failed to run nsxMigration for the custom resource (%s): (%s)", migratensx.Name, err)})

		if err := r.Status().Update(ctx, migratensx); err != nil {
			log.Error(err, "Failed to update nsxMigration status")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, err
	}

	// The following implementation will update the status
	meta.SetStatusCondition(&migratensx.Status.Conditions, metav1.Condition{Type: typeAvailableNSXMigration,
		Status: metav1.ConditionTrue, Reason: "Reconciling",
		Message: fmt.Sprintf("migrate nsx for migration spec at %s completed successfully", migratensx.Name)})

	if err := r.Status().Update(ctx, migratensx); err != nil {
		log.Error(err, "Failed to update migratensx status")
		return ctrl.Result{}, err
	}

	log.Info("finished the Reconcile without error")
	// stop the Reconcile
	return ctrl.Result{}, nil
}

type nsxConn struct {
	user               string
	password           string
	url                string
	insecureSkipVerify bool
}

func (n *nsxConn) getUser(s *v1.Secret) {
	if userData, found := s.Data["username"]; found {
		n.user = string(userData)
	}
}

func (n *nsxConn) getPassword(s *v1.Secret) {
	if passwordData, found := s.Data["password"]; found {
		n.password = string(passwordData)
	}
}

func (n *nsxConn) getURL(s *v1.Secret) {
	if urlData, found := s.Data["url"]; found {
		n.url = string(urlData)
	}
}

func (n *nsxConn) getInsecureSkipVerify(s *v1.Secret) {
	insecure, found := s.Data["insecureSkipVerify"]
	if !found {
		return
	}

	insecureSkipVerify, err := strconv.ParseBool(string(insecure))
	if err != nil {
		return
	}

	n.insecureSkipVerify = insecureSkipVerify
}

func (r *NSXMigrationReconciler) genConfigMap(data map[string]string, name string, ctx context.Context, log logr.Logger) error {
	// test create configmap
	cm := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Data: data,
	}
	if err := r.Create(ctx, cm); err != nil {
		log.Error(err, "Failed to create ConfigMap",
			"ConfigMap.Namespace", cm.Namespace, "ConfigMap.Name", cm.Name)
		return err
	}

	log.Info("generated configmap", "ConfigMap.Namespace", cm.Namespace, "ConfigMap.Name", cm.Name)
	return nil
}

func (r *NSXMigrationReconciler) getNSXCredentials(cr *nsxv1alpha1.NSXMigration, ctx context.Context, log logr.Logger) (conn *nsxConn, err error) {
	// TODO: initial step: connect to NSX host from spec, validate connection is OK, print to log the results.
	ref := cr.Spec.Secret
	nsName := types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}
	log.Info("called nsxMigration() to fetch secret", "NamespacedName", nsName.String())
	// get the secret from spec

	secret := &v1.Secret{}
	if err := r.Get(ctx, nsName, secret); err != nil {
		log.Error(err, "Failed to get secret ref", "namespace", ref.Namespace, "name", ref.Name)
		log.Error(err, "error is:", "errorStr", err.Error())
		return nil, err
	}

	log.Info("completed Get Secrete without error")

	// get nsx credentials from secret
	//var user, password, url string
	conn = &nsxConn{}

	conn.getUser(secret)
	conn.getPassword(secret)
	conn.getURL(secret)
	conn.getInsecureSkipVerify(secret)

	log.Info("extracted nsx credentials", "user", conn.user, "url", conn.url)

	// next: validate nsx connection with given credentials
	res, err := collector.ValidateNSXConnection(conn.url, conn.user, conn.password, !conn.insecureSkipVerify)
	if err != nil {
		log.Error(err, "REST API call error", "errStr", err.Error())
		return nil, err
	}
	log.Info("REST API call returned successfully", "response", res)

	return conn, nil
}

func (r *NSXMigrationReconciler) nsxMigration(cr *nsxv1alpha1.NSXMigration, ctx context.Context, log logr.Logger) error {

	conn, err := r.getNSXCredentials(cr, ctx, log)
	if err != nil {
		return err
	}

	runnerObj, err := runner.NewRunnerWithOptionsList(
		runner.WithHighVerbosity(true),
		runner.WithLogFile("debug/log.txt"),
		runner.WithNSXURL(conn.url),
		runner.WithNSXUser(conn.user),
		runner.WithNSXPassword(conn.password),
		runner.WithDisableInsecureSkipVerify(!conn.insecureSkipVerify),
		runner.WithSynth(true),
	)
	if err != nil {
		return err
	}

	runObservations, err := runnerObj.Run()
	if err != nil {
		log.Error(err, "runner.Run() returned with error", "errStr", err.Error())
		return err
	}

	policies, _ := runnerObj.GetGeneratedPolicies()
	jsonOut, err := runObservations.ConfigAsJSON()
	if err != nil {
		log.Error(err, "runner.ConfigAsJSON() returned with error", "errStr", err.Error())
		return err
	}

	// build configmaps from jsonOut

	if err := r.genConfigMap(map[string]string{"topology": jsonOut.Topology}, "topology-"+cr.Name, ctx, log); err != nil {
		return err
	}
	if err := r.genConfigMap(map[string]string{"segmentation": jsonOut.Segmentation}, "segmentation-"+cr.Name, ctx, log); err != nil {
		return err
	}
	if err := r.genConfigMap(map[string]string{"connectivity": jsonOut.Connectivity}, "connectivity-"+cr.Name, ctx, log); err != nil {
		return err
	}
	if err := r.genConfigMap(map[string]string{"generated-netpols": jsonOut.GeneratedNetpols}, "generated-netpols-"+cr.Name, ctx, log); err != nil {
		return err
	}

	log.Info("NSXToK8sSynthesis returned with policies", "numPolicies", len(policies))

	/*for _, policy := range policies {
		if policy.Namespace == "" {
			policy.Namespace = v1.NamespaceDefault
		}
		if err = r.Create(ctx, policy); err != nil {
			log.Error(err, "Failed to create new NetworkPolicy",
				"NetworkPolicy.Namespace", policy.Namespace, "NetworkPolicy.Name", policy.Name)
			return err
		}
	}*/

	// NetworkPolicy created successfully

	log.Info("NetworkPolicy created successfully")

	return nil
}

// finalizeMemcached will perform the required operations before delete the CR.
/*func (r *NSXMigrationReconciler) doFinalizerOperationsForMigrateNSX(cr *nsxv1alpha1.NSXMigration) {
	// TODO(user): Add the cleanup steps that the operator
	// needs to do before the CR can be deleted. Examples
	// of finalizers include performing backups and deleting
	// resources that are not owned by this CR, like a PVC.

	// Note: It is not recommended to use finalizers with the purpose of deleting resources which are
	// created and managed in the reconciliation. These ones, such as the Deployment created on this reconcile,
	// are defined as dependent of the custom resource. See that we use the method ctrl.SetControllerReference.
	// to set the ownerRef which means that the Deployment will be deleted by the Kubernetes API.
	// More info: https://kubernetes.io/docs/tasks/administer-cluster/use-cascading-deletion/

	// The following implementation will raise an event
	r.Recorder.Event(cr, "Warning", "Deleting",
		fmt.Sprintf("Custom Resource %s is being deleted from the namespace %s",
			cr.Name,
			cr.Namespace))
}*/

// SetupWithManager sets up the controller with the Manager.
func (r *NSXMigrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nsxv1alpha1.NSXMigration{}). // NSXMigration type as the primary resource to watch
		// For each NSXMigration type Add/Update/Delete event the reconcile loop will be sent a reconcile Request (a namespace/name key) for that NSXMigration object.
		WithOptions(controller.Options{MaxConcurrentReconciles: 2}).
		Complete(r)
}
