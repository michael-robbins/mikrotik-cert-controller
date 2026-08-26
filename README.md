# mikrotik-cert-controller

A Kubernetes operator that watches [cert-manager](https://cert-manager.io/) TLS Secrets and automatically syncs certificates to [MikroTik](https://mikrotik.com/) RouterOS devices via SSH/SFTP.

When cert-manager renews a certificate, mikrotik-cert-controller uploads the new cert (including the full chain) to your routers and assigns it to configured services — www-ssl, api-ssl, or IPsec identities/peers.

## Features

- Watches Kubernetes Secrets labeled `cert-controller.mikrotik.io/enabled=true`
- Namespace-scoped deployment (secure Role/RoleBinding and cache-scoping by default)
- Uploads leaf certificate, private key, and intermediate chain certs separately
- Handles MikroTik's certificate deduplication (looks up chain certs by common name)
- Assigns certificates to RouterOS services: `www-ssl`, `api-ssl`, `ipsec`
- SSH host key verification via `known_hosts`
- Per-router SSH key overrides
- Prometheus metrics (sync duration, cert expiry, error counts)
- Health/readiness endpoints
- Finalizer-based cleanup on Secret deletion (configurable)
- Multi-arch container images (amd64, arm64)

## Quick Start

### Prerequisites

- Kubernetes cluster with cert-manager installed
- MikroTik router(s) accessible via SSH from the cluster
- SSH key pair for router authentication

### 1. Create the namespace and SSH key Secret

```bash
kubectl create namespace mikrotik-cert-controller

kubectl create secret generic mikrotik-cert-controller-ssh-key \
  --namespace=mikrotik-cert-controller \
  --from-file=ssh-privatekey=/path/to/id_ed25519
```

### 2. Get router SSH host keys

```bash
ssh-keyscan -p 22 192.168.88.1 2>/dev/null
```

Add the output to `k8s/known_hosts`.

### 3. Configure routers

Edit `k8s/config.yaml`:

```yaml
routers:
  - name: my-router
    address: 192.168.88.1
    username: admin
    services:
      - type: www-ssl
      - type: api-ssl
      - type: ipsec
        identity_name: ike2-rw-id
```

### 4. Deploy

```bash
# Using kustomize
kubectl apply -k k8s/

# Or using the kustomize overlay
kubectl apply -k deploy/kustomize/overlays/production/
```

### 5. Label your cert-manager Secret

```bash
kubectl label secret my-tls-cert cert-controller.mikrotik.io/enabled=true
```

The operator will detect the labeled Secret and sync the certificate to all configured routers.

## Configuration

### Config file reference

| Field | Default | Description |
|-------|---------|-------------|
| `log_level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `label_selector` | `cert-controller.mikrotik.io/enabled=true` | Label selector for Secrets to watch |
| `watch_namespace` | | Restricts the operator to watching Secrets in a single namespace (e.g. `mikrotik-certs`). If empty, watches all namespaces (cluster-scoped). |
| `sync_period` | `1h` | How often to re-check all Secrets |
| `delete_policy` | `retain` | `retain` or `remove` — what to do with router certs when the Secret is deleted |
| `metrics_bind_address` | `:8080` | Address the Prometheus metrics server listens on. `0` disables it |
| `health_probe_bind_address` | `:8081` | Address the health/readiness probe server listens on. `0` disables it |
| `ssh_port` | `22` | Default SSH port for all routers |
| `ssh_key` | | Global SSH key Secret reference |
| `known_hosts_file` | | Path to known_hosts file for SSH host key verification |
| `insecure_ignore_host_key` | `false` | Skip SSH host key verification (not recommended) |
| `routers` | `[]` | List of MikroTik router targets |

### Router configuration

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique name for this router (used in metrics and logs) |
| `address` | yes | Router IP or hostname |
| `username` | yes | SSH username |
| `ssh_port` | no | Override the global SSH port |
| `ssh_key` | no | Override the global SSH key reference |
| `services` | no | List of services to assign the certificate to |

### Service types

| Type | Extra fields | Description |
|------|-------------|-------------|
| `www-ssl` | none | RouterOS web management HTTPS |
| `api-ssl` | none | RouterOS API SSL |
| `ipsec` | `peer_name` and/or `identity_name` | IPsec peer/identity certificate |

### Environment variable overrides

All config fields can be overridden with environment variables prefixed with `CERTCTL_`:

```bash
CERTCTL_LOG_LEVEL=debug
CERTCTL_SSH_PORT=2222
CERTCTL_METRICS_BIND_ADDRESS=:9080
CERTCTL_HEALTH_PROBE_BIND_ADDRESS=:9081
```

## Security & RBAC Scoping

To adhere to the principle of least privilege, `mikrotik-cert-controller` can be deployed in either **Namespace-scoped** mode or **Cluster-scoped** mode:

### 1. Namespace-scoped Mode (Recommended & Default)
In this mode, the operator has access to read Secrets and manage leader election resources *only* within the local deployment namespace (e.g. `mikrotik-certs`).
- Uses `rbac-namespace.yaml` (which defines local `Role` and `RoleBinding`).
- Configure `watch_namespace` (or env variable `CERTCTL_WATCH_NAMESPACE`) to the target namespace to optimize operator runtime cache.

### 2. Cluster-scoped Mode
In this mode, the operator has access to watch and synchronize Secrets across the entire cluster.
- Uses `rbac-cluster.yaml` (which defines a `ClusterRole` and `ClusterRoleBinding`).
- Leave `watch_namespace` empty.

To choose which RBAC version is applied during deployment, see `k8s/kustomization.yaml` or `deploy/kustomize/base/kustomization.yaml` and adjust the active resource.

## How it works

1. The operator watches Kubernetes Secrets matching the label selector
2. When a Secret changes, it computes a SHA-256 hash of `tls.crt` + `tls.key`
3. If the hash differs from the annotation `mikrotik-cert-controller.io/last-synced-hash`, a sync is triggered
4. For each configured router:
   - Connect via SSH
   - Split the PEM bundle into leaf and chain certificates
   - Upload each file via SFTP
   - Remove old certificates matching the domain
   - Import chain certs first, then leaf cert + key
   - Look up chain certs by common name (handles MikroTik deduplication)
   - Assign the full chain to configured services
   - Clean up uploaded files
5. On success, update the Secret annotations with the new hash and timestamp

## Metrics

Served on `:8080/metrics` by default. Change the address with `metrics_bind_address`
(or `CERTCTL_METRICS_BIND_ADDRESS`) — needed when running with `hostNetwork: true` on a
node where port 8080 is already taken — or set it to `0` to disable the metrics server.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `certsync_syncs_total` | counter | `router`, `status` | Total sync operations |
| `certsync_errors_total` | counter | `router`, `phase` | Errors by phase (connect, upload, import, verify, assign) |
| `certsync_sync_duration_seconds` | histogram | `router` | Sync duration per router |
| `certsync_cert_expiry_timestamp` | gauge | `domain`, `router` | Certificate expiry as Unix timestamp |

## Building

```bash
make build          # Build binary
make test           # Run tests with race detector
make docker-build   # Build container image
```

## License

MIT — see [LICENSE](LICENSE).
