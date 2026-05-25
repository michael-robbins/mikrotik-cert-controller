// Package controller implements the Kubernetes Secret reconciler
// for syncing certificates to MikroTik routers.
package controller

import (
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// LabelPredicate returns a predicate that only passes events for objects
// matching the given label selector.
func LabelPredicate(selector labels.Selector) predicate.Funcs {
	matches := func(l map[string]string) bool {
		if selector == nil {
			return true
		}
		return selector.Matches(labels.Set(l))
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return matches(e.Object.GetLabels())
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return matches(e.ObjectNew.GetLabels())
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return matches(e.Object.GetLabels())
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return matches(e.Object.GetLabels())
		},
	}
}
