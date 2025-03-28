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

package v1alpha1

import (
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NSXMigrationSpec defines the desired state of NSXMigration
type NSXMigrationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// The nsx Host URL.
	URL string `json:"url,omitempty"`
	// References a secret containing credentials and
	// other confidential information.
	Secret core.ObjectReference `json:"secret" ref:"Secret"`
}

// NSXMigrationStatus defines the observed state of NSXMigration
type NSXMigrationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Represents the observations of a MigrateNSX's current state.
	// MigrateNSX.status.conditions.type are: "Available", "Progressing", and "Degraded"
	// MigrateNSX.status.conditions.status are one of True, False, Unknown.
	// MigrateNSX.status.conditions.reason the value should be a CamelCase string and producers of specific
	// condition types may define expected values and meanings for this field, and whether the values
	// are considered a guaranteed API.
	// Memcached.status.conditions.Message is a human readable message indicating details about the transition.
	// For further information see: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// Conditions store the status conditions of the MigrateNSX instances
	// +operator-sdk:csv:customresourcedefinitions:type=status
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NSXMigration is the Schema for the nsxmigrations API
// +kubebuilder:subresource:status
type NSXMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NSXMigrationSpec   `json:"spec,omitempty"`
	Status NSXMigrationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NSXMigrationList contains a list of NSXMigration
type NSXMigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NSXMigration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NSXMigration{}, &NSXMigrationList{})
}
