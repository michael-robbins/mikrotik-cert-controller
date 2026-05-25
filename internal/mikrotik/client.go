// Package mikrotik provides SSH/SCP communication with MikroTik routers.
package mikrotik

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Client communicates with a MikroTik router via SSH.
type Client interface {
	// Upload writes content to a file on the router via SFTP.
	Upload(ctx context.Context, filename string, content []byte) error
	// Execute runs a RouterOS command and returns stdout.
	Execute(ctx context.Context, command string) (string, error)
	// Close terminates the SSH connection.
	Close() error
}

// ConnectInput contains parameters for connecting to a router.
type ConnectInput struct {
	Address    string
	Port       int
	Username   string
	PrivateKey []byte
	Timeout    time.Duration
	HostKey    HostKeyChecker
}

// HostKeyChecker provides SSH host key verification.
type HostKeyChecker interface {
	Callback() ssh.HostKeyCallback
}

type hostKeyCallbackFunc struct{ cb ssh.HostKeyCallback }

func (h hostKeyCallbackFunc) Callback() ssh.HostKeyCallback { return h.cb }

// InsecureIgnoreHostKeyChecker disables host key verification.
func InsecureIgnoreHostKeyChecker() HostKeyChecker {
	return hostKeyCallbackFunc{cb: ssh.InsecureIgnoreHostKey()}
}

// KnownHostsFileChecker verifies host keys using an OpenSSH known_hosts file.
// The file is parsed eagerly; an error is returned if the file cannot be read.
func KnownHostsFileChecker(path string) (HostKeyChecker, error) {
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	return hostKeyCallbackFunc{cb: cb}, nil
}

// sshClient implements Client using SSH/SFTP.
type sshClient struct {
	conn *ssh.Client
}

// Connect establishes an SSH connection to a MikroTik router.
func Connect(ctx context.Context, in ConnectInput) (Client, error) {
	signer, err := ssh.ParsePrivateKey(in.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}

	var hostKeyCallback ssh.HostKeyCallback
	if in.HostKey != nil {
		hostKeyCallback = in.HostKey.Callback()
	}
	if hostKeyCallback == nil {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	config := &ssh.ClientConfig{
		User: in.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         in.Timeout,
	}

	addr := net.JoinHostPort(in.Address, fmt.Sprintf("%d", in.Port))

	// Context-aware connection (GS-1)
	type connResult struct {
		client *ssh.Client
		err    error
	}
	done := make(chan connResult, 1)
	go func() {
		client, err := ssh.Dial("tcp", addr, config)
		done <- connResult{client, err}
	}()

	select {
	case <-ctx.Done():
		go func() {
			r := <-done
			if r.client != nil {
				_ = r.client.Close()
			}
		}()
		return nil, fmt.Errorf("connect to %s: %w", addr, ctx.Err())
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("SSH dial %s: %w", addr, r.err)
		}
		return &sshClient{conn: r.client}, nil
	}
}

// Upload writes content to a file on the router via SFTP.
func (c *sshClient) Upload(ctx context.Context, filename string, content []byte) error {
	sftpClient, err := sftp.NewClient(c.conn)
	if err != nil {
		return fmt.Errorf("create SFTP client: %w", err)
	}

	var sftpOnce sync.Once
	closeSFTP := func() { sftpOnce.Do(func() { _ = sftpClient.Close() }) }
	defer closeSFTP()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("upload %s: %w", filename, err)
	}

	f, err := sftpClient.Create(filename)
	if err != nil {
		return fmt.Errorf("create remote file %s: %w", filename, err)
	}

	var fileOnce sync.Once
	closeFile := func() { fileOnce.Do(func() { _ = f.Close() }) }
	defer closeFile()

	cancelDone := make(chan struct{})
	defer close(cancelDone)
	go func() {
		select {
		case <-ctx.Done():
			closeFile()
			closeSFTP()
		case <-cancelDone:
		}
	}()

	if _, err := f.Write(content); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("upload %s: %w", filename, ctx.Err())
		}
		return fmt.Errorf("write remote file %s: %w", filename, err)
	}
	return nil
}

// Execute runs a RouterOS command and returns stdout.
func (c *sshClient) Execute(ctx context.Context, command string) (string, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("create SSH session: %w", err)
	}

	var sessionOnce sync.Once
	closeSession := func() { sessionOnce.Do(func() { _ = session.Close() }) }
	defer closeSession()

	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("execute %q: %w", command, err)
	}

	cancelDone := make(chan struct{})
	defer close(cancelDone)
	go func() {
		select {
		case <-ctx.Done():
			closeSession()
		case <-cancelDone:
		}
	}()

	out, err := session.CombinedOutput(command)
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("execute %q: %w (output: %s)", command, ctx.Err(), string(out))
	}
	if err != nil {
		return string(out), fmt.Errorf("execute %q: %w (output: %s)", command, err, string(out))
	}
	return string(out), nil
}

// Close terminates the SSH connection.
func (c *sshClient) Close() error {
	return c.conn.Close()
}
