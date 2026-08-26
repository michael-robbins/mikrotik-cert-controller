// Package main is the entrypoint for the mikrotik-cert-controller.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yannick/mikrotik-cert-controller/internal/config"
	"github.com/yannick/mikrotik-cert-controller/internal/controller"
	"github.com/yannick/mikrotik-cert-controller/internal/mikrotik"
	certctl "github.com/yannick/mikrotik-cert-controller/internal/sync"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:     "cert-controller",
		Short:   "Sync cert-manager certificates to MikroTik routers",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(configFile)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "/etc/cert-controller/config.yaml", "path to config file")

	return cmd
}

func run(configFile string) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Setup structured logging
	level := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("starting mikrotik-cert-controller", "version", version)

	// Parse label selector for cache filtering
	selector, err := labels.Parse(cfg.LabelSelector)
	if err != nil {
		return fmt.Errorf("parse label selector %q: %w", cfg.LabelSelector, err)
	}

	// Setup controller manager
	cacheOpts := cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Label: selector,
			},
		},
	}
	if cfg.WatchNamespace != "" {
		logger.Info("restricting cache to watch namespace", "namespace", cfg.WatchNamespace)
		cacheOpts.DefaultNamespaces = map[string]cache.Config{
			cfg.WatchNamespace: {},
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Cache:                  cacheOpts,
		HealthProbeBindAddress: cfg.HealthProbeBindAddress,
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsBindAddress,
		},
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// Health endpoints
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz check: %w", err)
	}

	// Setup sync engine
	engine, err := certctl.NewEngine(certctl.NewEngineInput{
		Connect:               mikrotik.Connect,
		Logger:                logger,
		KnownHostsFile:        cfg.KnownHostsFile,
		InsecureIgnoreHostKey: cfg.InsecureIgnoreHostKey,
	})
	if err != nil {
		return fmt.Errorf("create sync engine: %w", err)
	}

	// Setup reconciler
	reconciler := &controller.Reconciler{
		Client:     mgr.GetClient(),
		Config:     cfg,
		Engine:     engine,
		Logger:     logger,
		Selector:   selector,
		SSHKeyFunc: controller.GetSSHKeyFromSecret(mgr.GetAPIReader()),
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup controller: %w", err)
	}

	logger.Info("starting manager",
		"routers", len(cfg.Routers),
		"sync_period", cfg.SyncPeriod,
		"delete_policy", cfg.DeletePolicy,
		"metrics_bind_address", cfg.MetricsBindAddress,
		"health_probe_bind_address", cfg.HealthProbeBindAddress,
	)

	return mgr.Start(ctrl.SetupSignalHandler())
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
