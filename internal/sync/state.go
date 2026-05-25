// Package sync provides certificate synchronization orchestration
// and annotation-based state tracking.
package sync

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

const (
	// AnnotationHash stores the SHA-256 hash of the last synced cert+key.
	AnnotationHash = "cert-controller.mikrotik.io/last-synced-hash"
	// AnnotationTimestamp stores the ISO 8601 timestamp of the last successful sync.
	AnnotationTimestamp = "cert-controller.mikrotik.io/last-synced-at"
	// AnnotationRouters stores a comma-separated list of routers that were synced.
	AnnotationRouters = "cert-controller.mikrotik.io/synced-routers"
	// Finalizer is the finalizer name for cleanup on deletion.
	Finalizer = "cert-controller.mikrotik.io/finalizer"
	// LabelEnabled is the label that marks a Secret for syncing.
	LabelEnabled = "cert-controller.mikrotik.io/enabled"
)

// NeedsSync returns true if the Secret's cert content has changed since last sync.
func NeedsSync(secret *corev1.Secret, currentHash string) bool {
	if secret.Annotations == nil {
		return true
	}
	return secret.Annotations[AnnotationHash] != currentHash
}

// UpdateAnnotationsInput contains parameters for UpdateAnnotations.
type UpdateAnnotationsInput struct {
	Secret  *corev1.Secret
	Hash    string
	Routers []string
}

// UpdateAnnotations sets sync tracking annotations on the Secret.
func UpdateAnnotations(in UpdateAnnotationsInput) {
	if in.Secret.Annotations == nil {
		in.Secret.Annotations = make(map[string]string)
	}
	in.Secret.Annotations[AnnotationHash] = in.Hash
	in.Secret.Annotations[AnnotationTimestamp] = time.Now().UTC().Format(time.RFC3339)
	in.Secret.Annotations[AnnotationRouters] = strings.Join(in.Routers, ",")
}

// HasFinalizer checks if the Secret has the cert-controller finalizer.
func HasFinalizer(secret *corev1.Secret) bool {
	for _, f := range secret.Finalizers {
		if f == Finalizer {
			return true
		}
	}
	return false
}

// AddFinalizer adds the cert-controller finalizer to the Secret.
func AddFinalizer(secret *corev1.Secret) {
	if HasFinalizer(secret) {
		return
	}
	secret.Finalizers = append(secret.Finalizers, Finalizer)
}

// RemoveFinalizer removes the cert-controller finalizer from the Secret.
func RemoveFinalizer(secret *corev1.Secret) {
	filtered := make([]string, 0, len(secret.Finalizers))
	for _, f := range secret.Finalizers {
		if f != Finalizer {
			filtered = append(filtered, f)
		}
	}
	secret.Finalizers = filtered
}

// SyncedRouters returns the list of routers from the annotation.
func SyncedRouters(secret *corev1.Secret) []string {
	if secret.Annotations == nil {
		return nil
	}
	val := secret.Annotations[AnnotationRouters]
	if val == "" {
		return nil
	}
	return strings.Split(val, ",")
}

// CertFilename returns the upload filename for a domain's certificate.
func CertFilename(domain string) string {
	return domain + ".crt"
}

// KeyFilename returns the upload filename for a domain's private key.
func KeyFilename(domain string) string {
	return domain + ".key"
}

// ChainCertFilename returns the upload filename for a chain certificate.
// Index 0 is the first intermediate, 1 is the second, etc.
func ChainCertFilename(domain string, index int) string {
	return fmt.Sprintf("%s.chain-%d.crt", domain, index)
}
