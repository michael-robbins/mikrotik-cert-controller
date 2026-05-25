package sync

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/yannick/mikrotik-cert-controller/internal/cert"
	"github.com/yannick/mikrotik-cert-controller/internal/config"
	"github.com/yannick/mikrotik-cert-controller/internal/metrics"
	"github.com/yannick/mikrotik-cert-controller/internal/mikrotik"
)

// ConnectFunc creates a mikrotik.Client for the given input.
// Abstracted for testing.
type ConnectFunc func(ctx context.Context, in mikrotik.ConnectInput) (mikrotik.Client, error)

// Engine orchestrates certificate syncing to MikroTik routers.
type Engine struct {
	connect ConnectFunc
	logger  *slog.Logger
	hostKey mikrotik.HostKeyChecker
}

// NewEngineInput contains parameters for creating an Engine.
type NewEngineInput struct {
	Connect               ConnectFunc
	Logger                *slog.Logger
	KnownHostsFile        string
	InsecureIgnoreHostKey bool
}

// NewEngine creates a sync engine with the given connection function.
// Returns an error if the known_hosts file cannot be parsed.
func NewEngine(in NewEngineInput) (*Engine, error) {
	var checker mikrotik.HostKeyChecker
	if in.InsecureIgnoreHostKey {
		checker = mikrotik.InsecureIgnoreHostKeyChecker()
	} else if in.KnownHostsFile != "" {
		var err error
		checker, err = mikrotik.KnownHostsFileChecker(in.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("setup host key verification: %w", err)
		}
	}

	return &Engine{
		connect: in.Connect,
		logger:  in.Logger,
		hostKey: checker,
	}, nil
}

// SyncInput contains parameters for a sync operation.
type SyncInput struct {
	CertInfo   *cert.Info
	CertPEM    []byte
	KeyPEM     []byte
	Router     config.Router
	SSHPort    int
	PrivateKey []byte
	Services   []config.Service
}

// SyncToRouter uploads and imports a certificate to a single router,
// then assigns it to configured services.
func (e *Engine) SyncToRouter(ctx context.Context, in SyncInput) error {
	logger := e.logger.With("router", in.Router.Name, "cert", in.CertInfo.DomainName)
	start := time.Now()

	client, err := e.connect(ctx, mikrotik.ConnectInput{
		Address:    in.Router.Address,
		Port:       in.SSHPort,
		Username:   in.Router.Username,
		PrivateKey: in.PrivateKey,
		Timeout:    10 * time.Second,
		HostKey:    e.hostKey,
	})
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues(in.Router.Name, "connect").Inc()
		return fmt.Errorf("connect to %s: %w", in.Router.Name, err)
	}
	defer client.Close()

	leafPEM, chainPEMs := cert.SplitPEMChain(in.CertPEM)
	certFile := CertFilename(in.CertInfo.DomainName)
	keyFile := KeyFilename(in.CertInfo.DomainName)

	// Build list of chain cert filenames for upload
	var chainFiles []string
	for i := range chainPEMs {
		chainFiles = append(chainFiles, ChainCertFilename(in.CertInfo.DomainName, i))
	}

	// Upload leaf cert, key, and each chain cert
	logger.Info("uploading certificate files", "chain_certs", len(chainPEMs))
	if err := client.Upload(ctx, certFile, leafPEM); err != nil {
		metrics.ErrorsTotal.WithLabelValues(in.Router.Name, "upload").Inc()
		return fmt.Errorf("upload cert to %s: %w", in.Router.Name, err)
	}
	if err := client.Upload(ctx, keyFile, in.KeyPEM); err != nil {
		metrics.ErrorsTotal.WithLabelValues(in.Router.Name, "upload").Inc()
		return fmt.Errorf("upload key to %s: %w", in.Router.Name, err)
	}
	for i, chainPEM := range chainPEMs {
		if err := client.Upload(ctx, chainFiles[i], chainPEM); err != nil {
			metrics.ErrorsTotal.WithLabelValues(in.Router.Name, "upload").Inc()
			return fmt.Errorf("upload chain cert %d to %s: %w", i, in.Router.Name, err)
		}
	}

	// Clean up uploaded files when we're done, regardless of success or failure.
	defer func() {
		logger.Info("cleaning up uploaded files")
		if _, err := client.Execute(ctx, mikrotik.RemoveFile(certFile)); err != nil {
			logger.Warn("failed to remove cert file", "error", err)
		}
		if _, err := client.Execute(ctx, mikrotik.RemoveFile(keyFile)); err != nil {
			logger.Warn("failed to remove key file", "error", err)
		}
		for _, f := range chainFiles {
			if _, err := client.Execute(ctx, mikrotik.RemoveFile(f)); err != nil {
				logger.Warn("failed to remove chain cert file", "file", f, "error", err)
			}
		}
	}()

	// Remove old certs matching this domain (leaf and chain)
	if err := e.removeOldCerts(ctx, client, in.CertInfo.DomainName, in.Router.Name); err != nil {
		logger.Warn("failed to remove old certs, continuing", "error", err)
	}

	// Import chain certs first (intermediates), then leaf cert + key
	for i, f := range chainFiles {
		logger.Info("importing chain certificate", "index", i)
		if _, err := client.Execute(ctx, mikrotik.ImportCert(f, "")); err != nil {
			metrics.ErrorsTotal.WithLabelValues(in.Router.Name, "import").Inc()
			return fmt.Errorf("import chain cert %d on %s: %w", i, in.Router.Name, err)
		}
	}
	logger.Info("importing leaf certificate")
	if _, err := client.Execute(ctx, mikrotik.ImportCert(certFile, "")); err != nil {
		metrics.ErrorsTotal.WithLabelValues(in.Router.Name, "import").Inc()
		return fmt.Errorf("import cert on %s: %w", in.Router.Name, err)
	}
	if _, err := client.Execute(ctx, mikrotik.ImportKey(keyFile)); err != nil {
		metrics.ErrorsTotal.WithLabelValues(in.Router.Name, "import").Inc()
		return fmt.Errorf("import key on %s: %w", in.Router.Name, err)
	}

	// Verify leaf cert import and build full chain string for service assignment
	certChain, err := e.verifyCertChain(ctx, client, in.CertInfo.DomainName, chainPEMs, in.Router.Name)
	if err != nil {
		return err
	}

	// Assign to services with full chain
	if err := e.assignServices(ctx, client, certChain, in.Services, in.Router.Name); err != nil {
		return err
	}

	// Record metrics on success
	metrics.SyncDuration.WithLabelValues(in.Router.Name).Observe(time.Since(start).Seconds())
	metrics.CertExpiry.WithLabelValues(in.CertInfo.DomainName, in.Router.Name).Set(
		float64(in.CertInfo.NotAfter.Unix()),
	)
	metrics.SyncsTotal.WithLabelValues(in.Router.Name, "success").Inc()

	logger.Info("certificate synced successfully", "cert_chain", certChain)
	return nil
}

// removeOldCerts removes existing certificates with the given domain prefix.
func (e *Engine) removeOldCerts(ctx context.Context, client mikrotik.Client, domain, router string) error {
	output, err := client.Execute(ctx, mikrotik.PrintCertByName(domain))
	if err != nil {
		return fmt.Errorf("list certs on %s: %w", router, err)
	}

	entries := mikrotik.ParseCertList(output)
	old := mikrotik.FindCertsByDomain(entries, domain)

	for _, entry := range old {
		e.logger.Info("removing old certificate", "router", router, "cert", entry.Name)
		if _, err := client.Execute(ctx, mikrotik.RemoveCert(entry.Name)); err != nil {
			return fmt.Errorf("remove cert %s on %s: %w", entry.Name, router, err)
		}
	}

	return nil
}

// verifyCertChain checks that the leaf certificate was imported with a private key,
// then discovers the imported chain cert names and returns a comma-separated chain
// string suitable for MikroTik service assignment (e.g. "leaf,intermediate,root").
func (e *Engine) verifyCertChain(ctx context.Context, client mikrotik.Client, domain string, chainPEMs [][]byte, router string) (string, error) {
	// Find the leaf cert (must have private key)
	output, err := client.Execute(ctx, mikrotik.PrintCertByName(domain))
	if err != nil {
		metrics.ErrorsTotal.WithLabelValues(router, "verify").Inc()
		return "", fmt.Errorf("verify cert on %s: %w", router, err)
	}

	entries := mikrotik.ParseCertList(output)
	certs := mikrotik.FindCertsByDomain(entries, domain)

	var leafName string
	for _, entry := range certs {
		if entry.PrivateKey {
			leafName = entry.Name
			break
		}
	}
	if leafName == "" {
		metrics.ErrorsTotal.WithLabelValues(router, "verify").Inc()
		return "", fmt.Errorf("no certificate with private key found for %q on %s", domain, router)
	}

	// Build chain: leaf first, then each chain cert.
	// MikroTik deduplicates certificates — if an intermediate already exists
	// under a different name, importing it again won't create a new entry.
	// We look up chain certs by their common name (parsed from the PEM) rather
	// than by the upload filename prefix, which handles deduplication correctly.
	chain := []string{leafName}
	for i, chainPEM := range chainPEMs {
		cn := cert.ParseCommonName(chainPEM)
		if cn == "" {
			e.logger.Warn("failed to parse chain cert CN", "index", i)
			continue
		}
		output, err := client.Execute(ctx, mikrotik.PrintCertByCommonName(cn))
		if err != nil {
			e.logger.Warn("failed to find chain cert by CN", "index", i, "cn", cn, "error", err)
			continue
		}
		chainEntries := mikrotik.ParseCertList(output)
		if len(chainEntries) > 0 {
			chain = append(chain, chainEntries[0].Name)
			e.logger.Info("found chain cert", "index", i, "cn", cn, "name", chainEntries[0].Name)
		} else {
			e.logger.Warn("chain cert not found after import", "index", i, "cn", cn)
		}
	}

	return strings.Join(chain, ","), nil
}

// assignServices binds the certificate to the configured MikroTik services.
func (e *Engine) assignServices(ctx context.Context, client mikrotik.Client, certName string, services []config.Service, router string) error {
	for _, svc := range services {
		cmds, err := serviceCommands(svc, certName)
		if err != nil {
			return err
		}

		for _, cmd := range cmds {
			e.logger.Info("assigning certificate to service", "router", router, "service", svc.Type, "cert", certName)
			if _, err := client.Execute(ctx, cmd); err != nil {
				metrics.ErrorsTotal.WithLabelValues(router, "assign").Inc()
				return fmt.Errorf("assign cert to %s on %s: %w", svc.Type, router, err)
			}
		}
	}

	return nil
}

// serviceCommands returns the RouterOS commands needed to assign a certificate to a service.
func serviceCommands(svc config.Service, certName string) ([]string, error) {
	switch svc.Type {
	case "www-ssl":
		return []string{mikrotik.SetWWWSSLCert(certName)}, nil
	case "api-ssl":
		return []string{mikrotik.SetAPISSLCert(certName)}, nil
	case "ipsec":
		var cmds []string
		if svc.PeerName != "" {
			cmds = append(cmds, mikrotik.SetIPsecPeerCert(svc.PeerName, certName))
		}
		if svc.IdentityName != "" {
			cmds = append(cmds, mikrotik.SetIPsecIdentityCert(svc.IdentityName, certName))
		}
		return cmds, nil
	default:
		return nil, fmt.Errorf("unknown service type %q", svc.Type)
	}
}

// RemoveFromRouter removes certificates matching the domain from a router.
func (e *Engine) RemoveFromRouter(ctx context.Context, in SyncInput) error {
	logger := e.logger.With("router", in.Router.Name, "cert", in.CertInfo.DomainName)

	client, err := e.connect(ctx, mikrotik.ConnectInput{
		Address:    in.Router.Address,
		Port:       in.SSHPort,
		Username:   in.Router.Username,
		PrivateKey: in.PrivateKey,
		Timeout:    10 * time.Second,
		HostKey:    e.hostKey,
	})
	if err != nil {
		return fmt.Errorf("connect to %s for removal: %w", in.Router.Name, err)
	}
	defer client.Close()

	// Best-effort: unassign from services first so certificate removal can succeed.
	for _, svc := range in.Services {
		cmds := UnassignService(svc)
		for _, cmd := range cmds {
			if _, err := client.Execute(ctx, cmd); err != nil {
				logger.Warn("failed to unassign certificate from service", "service", svc.Type, "error", err)
			}
		}
	}

	logger.Info("removing certificate from router")
	if err := e.removeOldCerts(ctx, client, in.CertInfo.DomainName, in.Router.Name); err != nil {
		return fmt.Errorf("remove certs from %s: %w", in.Router.Name, err)
	}

	return nil
}

// UnassignService returns the RouterOS commands to unset a certificate from a service.
// Each command should be executed individually. This is a best-effort operation used during cleanup.
func UnassignService(svc config.Service) []string {
	switch svc.Type {
	case "www-ssl":
		return []string{`/ip service set www-ssl certificate=""`}
	case "api-ssl":
		return []string{`/ip service set api-ssl certificate=""`}
	case "ipsec":
		var cmds []string
		if svc.PeerName != "" {
			cmds = append(cmds, fmt.Sprintf(`/ip ipsec peer set %q certificate=""`, svc.PeerName))
		}
		if svc.IdentityName != "" {
			cmds = append(cmds, fmt.Sprintf(`/ip ipsec identity set %q certificate=""`, svc.IdentityName))
		}
		return cmds
	default:
		return nil
	}
}
