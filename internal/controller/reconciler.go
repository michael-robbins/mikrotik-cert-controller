package controller

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yannick/mikrotik-cert-controller/internal/cert"
	"github.com/yannick/mikrotik-cert-controller/internal/config"
	"github.com/yannick/mikrotik-cert-controller/internal/metrics"
	certctl "github.com/yannick/mikrotik-cert-controller/internal/sync"
)

// Reconciler watches Secrets and syncs certificates to MikroTik routers.
type Reconciler struct {
	client.Client
	Config     *config.Config
	Engine     *certctl.Engine
	Logger     *slog.Logger
	Selector   labels.Selector
	SSHKeyFunc func(ctx context.Context, ref config.SSHKeyRef) ([]byte, error)
}

// Reconcile handles a single Secret reconciliation event.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.With("secret", req.NamespacedName)

	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion
	if !secret.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &secret, logger)
	}

	// Ensure finalizer if delete_policy=remove
	if r.Config.DeletePolicy == "remove" && !certctl.HasFinalizer(&secret) {
		certctl.AddFinalizer(&secret)
		if err := r.Update(ctx, &secret); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	// Parse cert data
	certPEM, ok := secret.Data["tls.crt"]
	if !ok {
		logger.Warn("secret missing tls.crt")
		return ctrl.Result{}, nil
	}
	keyPEM, ok := secret.Data["tls.key"]
	if !ok {
		logger.Warn("secret missing tls.key")
		return ctrl.Result{}, nil
	}

	info, err := cert.Parse(certPEM, keyPEM)
	if err != nil {
		logger.Error("failed to parse certificate", "error", err)
		return ctrl.Result{}, nil // don't requeue on parse failure
	}

	// Check if sync is needed
	if !certctl.NeedsSync(&secret, info.Hash) {
		logger.Debug("certificate unchanged, skipping sync")
		return ctrl.Result{RequeueAfter: r.Config.SyncPeriod}, nil
	}

	if len(r.Config.Routers) == 0 {
		logger.Warn("no routers configured; skipping sync")
		return ctrl.Result{RequeueAfter: r.Config.SyncPeriod}, nil
	}

	// Sync to each router
	logger.Info("syncing certificate", "domain", info.DomainName)
	var syncedRouters []string
	var failed bool

	for _, router := range r.Config.Routers {
		sshKeyRef := router.EffectiveSSHKey(r.Config.SSHKey)
		privateKey, err := r.SSHKeyFunc(ctx, sshKeyRef)
		if err != nil {
			logger.Error("failed to get SSH key", "router", router.Name, "error", err)
			metrics.ErrorsTotal.WithLabelValues(router.Name, "ssh_key").Inc()
			metrics.SyncsTotal.WithLabelValues(router.Name, "failure").Inc()
			failed = true
			continue
		}

		err = r.Engine.SyncToRouter(ctx, certctl.SyncInput{
			CertInfo:   info,
			CertPEM:    certPEM,
			KeyPEM:     keyPEM,
			Router:     router,
			SSHPort:    router.EffectiveSSHPort(r.Config.SSHPort),
			PrivateKey: privateKey,
			Services:   router.Services,
		})
		if err != nil {
			logger.Error("failed to sync to router", "router", router.Name, "error", err)
			metrics.SyncsTotal.WithLabelValues(router.Name, "failure").Inc()
			failed = true
			continue
		}

		syncedRouters = append(syncedRouters, router.Name)
	}

	if failed {
		// Don't record the new hash yet; retry sooner to converge failed routers.
		logger.Warn("sync incomplete; will retry", "synced_routers", syncedRouters)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Update annotations only when all routers succeeded.
	certctl.UpdateAnnotations(certctl.UpdateAnnotationsInput{Secret: &secret, Hash: info.Hash, Routers: syncedRouters})
	if err := r.Update(ctx, &secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("update annotations: %w", err)
	}

	return ctrl.Result{RequeueAfter: r.Config.SyncPeriod}, nil
}

// handleDeletion processes the finalizer when a Secret is deleted.
func (r *Reconciler) handleDeletion(ctx context.Context, secret *corev1.Secret, logger *slog.Logger) (ctrl.Result, error) {
	if !certctl.HasFinalizer(secret) {
		return ctrl.Result{}, nil
	}

	if r.Config.DeletePolicy == "remove" {
		certPEM := secret.Data["tls.crt"]
		keyPEM := secret.Data["tls.key"]
		if certPEM != nil && keyPEM != nil {
			info, err := cert.Parse(certPEM, keyPEM)
			if err == nil {
				for _, router := range r.Config.Routers {
					sshKeyRef := router.EffectiveSSHKey(r.Config.SSHKey)
					privateKey, err := r.SSHKeyFunc(ctx, sshKeyRef)
					if err != nil {
						logger.Error("failed to get SSH key for removal", "router", router.Name, "error", err)
						metrics.ErrorsTotal.WithLabelValues(router.Name, "ssh_key").Inc()
						continue
					}

					if err := r.Engine.RemoveFromRouter(ctx, certctl.SyncInput{
						CertInfo:   info,
						Router:     router,
						SSHPort:    router.EffectiveSSHPort(r.Config.SSHPort),
						PrivateKey: privateKey,
						Services:   router.Services,
					}); err != nil {
						logger.Error("failed to remove cert from router", "router", router.Name, "error", err)
						metrics.ErrorsTotal.WithLabelValues(router.Name, "removal").Inc()
					}
				}
			}
		}
	}

	certctl.RemoveFinalizer(secret)
	if err := r.Update(ctx, secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(LabelPredicate(r.Selector)).
		Complete(r)
}

// GetSSHKeyFromSecret retrieves an SSH private key from a Kubernetes Secret.
// Uses a Reader (typically mgr.GetAPIReader()) to bypass the label-filtered cache.
func GetSSHKeyFromSecret(r client.Reader) func(ctx context.Context, ref config.SSHKeyRef) ([]byte, error) {
	return func(ctx context.Context, ref config.SSHKeyRef) ([]byte, error) {
		var secret corev1.Secret
		key := types.NamespacedName{
			Name:      ref.SecretName,
			Namespace: ref.SecretNamespace,
		}
		if err := r.Get(ctx, key, &secret); err != nil {
			return nil, fmt.Errorf("get SSH key secret %s/%s: %w", ref.SecretNamespace, ref.SecretName, err)
		}

		data, ok := secret.Data[ref.SecretKey]
		if !ok {
			return nil, fmt.Errorf("SSH key secret %s/%s missing key %q", ref.SecretNamespace, ref.SecretName, ref.SecretKey)
		}

		return data, nil
	}
}
