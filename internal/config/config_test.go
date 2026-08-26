package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTestConfig(t, `
log_level: debug
label_selector: "cert-controller.mikrotik.io/enabled=true"
sync_period: 30m
delete_policy: retain
known_hosts_file: /tmp/known_hosts
ssh_port: 22
ssh_key:
  secret_name: my-ssh-key
  secret_namespace: cert-manager
  secret_key: ssh-privatekey
routers:
  - name: router-main
    address: 192.168.1.1
    username: admin
    services:
      - type: www-ssl
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if len(cfg.Routers) != 1 {
		t.Fatalf("len(Routers) = %d, want 1", len(cfg.Routers))
	}
	if cfg.Routers[0].Name != "router-main" {
		t.Errorf("Router name = %q, want %q", cfg.Routers[0].Name, "router-main")
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeTestConfig(t, `
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers:
  - name: r1
    address: 10.0.0.1
    username: admin
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, "info")
	}
	if cfg.SSHPort != 22 {
		t.Errorf("SSHPort = %d, want default 22", cfg.SSHPort)
	}
	if cfg.DeletePolicy != "retain" {
		t.Errorf("DeletePolicy = %q, want default %q", cfg.DeletePolicy, "retain")
	}
	if cfg.WatchNamespace != "" {
		t.Errorf("WatchNamespace = %q, want default %q", cfg.WatchNamespace, "")
	}
	if cfg.MetricsBindAddress != ":8080" {
		t.Errorf("MetricsBindAddress = %q, want default %q", cfg.MetricsBindAddress, ":8080")
	}
	if cfg.HealthProbeBindAddress != ":8081" {
		t.Errorf("HealthProbeBindAddress = %q, want default %q", cfg.HealthProbeBindAddress, ":8081")
	}
}

func TestLoad_WatchNamespace(t *testing.T) {
	path := writeTestConfig(t, `
watch_namespace: mikrotik-certs
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers:
  - name: r1
    address: 10.0.0.1
    username: admin
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.WatchNamespace != "mikrotik-certs" {
		t.Errorf("WatchNamespace = %q, want %q", cfg.WatchNamespace, "mikrotik-certs")
	}
}

func TestLoad_BindAddressesFromYAML(t *testing.T) {
	path := writeTestConfig(t, `
metrics_bind_address: 127.0.0.1:19080
health_probe_bind_address: 127.0.0.1:19081
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers:
  - name: r1
    address: 10.0.0.1
    username: admin
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.MetricsBindAddress != "127.0.0.1:19080" {
		t.Errorf("MetricsBindAddress = %q, want %q", cfg.MetricsBindAddress, "127.0.0.1:19080")
	}
	if cfg.HealthProbeBindAddress != "127.0.0.1:19081" {
		t.Errorf("HealthProbeBindAddress = %q, want %q", cfg.HealthProbeBindAddress, "127.0.0.1:19081")
	}
}

func TestLoad_BindAddressesFromEnv(t *testing.T) {
	path := writeTestConfig(t, `
metrics_bind_address: ":8080"
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers:
  - name: r1
    address: 10.0.0.1
    username: admin
`)

	t.Setenv("CERTCTL_METRICS_BIND_ADDRESS", ":19080")
	t.Setenv("CERTCTL_HEALTH_PROBE_BIND_ADDRESS", ":19081")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.MetricsBindAddress != ":19080" {
		t.Errorf("MetricsBindAddress = %q, want %q", cfg.MetricsBindAddress, ":19080")
	}
	if cfg.HealthProbeBindAddress != ":19081" {
		t.Errorf("HealthProbeBindAddress = %q, want %q", cfg.HealthProbeBindAddress, ":19081")
	}
}

func TestValidate_BindAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "port only", addr: ":8080"},
		{name: "host and port", addr: "127.0.0.1:8080"},
		{name: "disabled", addr: "0"},
		{name: "empty", addr: "", wantErr: true},
		{name: "no port", addr: "127.0.0.1", wantErr: true},
		{name: "not an address", addr: "8080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindAddress("metrics_bind_address", tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBindAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidate_NoRouters(t *testing.T) {
	path := writeTestConfig(t, `
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers: []
`)

	_, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error for empty routers, got %v", err)
	}
}

func TestValidate_InvalidDeletePolicy(t *testing.T) {
	path := writeTestConfig(t, `
delete_policy: destroy
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers:
  - name: r1
    address: 10.0.0.1
    username: admin
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid delete_policy")
	}
}

func TestValidate_InvalidServiceType(t *testing.T) {
	path := writeTestConfig(t, `
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers:
  - name: r1
    address: 10.0.0.1
    username: admin
    services:
      - type: invalid-type
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid service type")
	}
}

func TestValidate_IPsecRequiresName(t *testing.T) {
	path := writeTestConfig(t, `
ssh_key:
  secret_name: my-key
  secret_namespace: default
insecure_ignore_host_key: true
routers:
  - name: r1
    address: 10.0.0.1
    username: admin
    services:
      - type: ipsec
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for ipsec without peer_name or identity_name")
	}
}

func TestRouter_EffectiveSSHPort(t *testing.T) {
	r := Router{SSHPort: 2222}
	if got := r.EffectiveSSHPort(22); got != 2222 {
		t.Errorf("EffectiveSSHPort() = %d, want 2222", got)
	}

	r2 := Router{}
	if got := r2.EffectiveSSHPort(22); got != 22 {
		t.Errorf("EffectiveSSHPort() = %d, want 22", got)
	}
}

func TestRouter_EffectiveSSHKey(t *testing.T) {
	override := &SSHKeyRef{SecretName: "override"}
	global := SSHKeyRef{SecretName: "global"}

	r := Router{SSHKey: override}
	if got := r.EffectiveSSHKey(global); got.SecretName != "override" {
		t.Errorf("EffectiveSSHKey() = %q, want %q", got.SecretName, "override")
	}

	r2 := Router{}
	if got := r2.EffectiveSSHKey(global); got.SecretName != "global" {
		t.Errorf("EffectiveSSHKey() = %q, want %q", got.SecretName, "global")
	}
}
