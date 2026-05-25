// Package cert provides PEM parsing, certificate metadata extraction,
// and hash computation for certificate sync tracking.
package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Info holds parsed certificate metadata used for syncing.
type Info struct {
	CommonName string
	DNSNames   []string
	NotAfter   time.Time
	DomainName string // sanitized name for MikroTik file/cert naming
	Hash       string // SHA-256 hex digest of cert+key bytes
}

// Parse extracts certificate info from PEM-encoded cert and key data.
// It parses the first certificate in the chain to extract CN/SAN,
// and computes a hash over the full cert+key content for change detection.
func Parse(certPEM, keyPEM []byte) (*Info, error) {
	cert, err := parseLeafCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	// Validate key PEM is present
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode key PEM: no PEM block found")
	}

	domain := extractDomain(cert)
	hash := computeHash(certPEM, keyPEM)

	return &Info{
		CommonName: cert.Subject.CommonName,
		DNSNames:   cert.DNSNames,
		NotAfter:   cert.NotAfter,
		DomainName: domain,
		Hash:       hash,
	}, nil
}

func parseLeafCertificate(certPEM []byte) (*x509.Certificate, error) {
	var certs []*x509.Certificate
	remaining := certPEM
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("decode cert PEM: no PEM block found")
	}

	// Prefer leaf cert: BasicConstraintsValid==true and IsCA==false is a strong hint.
	for _, c := range certs {
		if c.BasicConstraintsValid && !c.IsCA {
			return c, nil
		}
	}

	// Fallback to the first cert.
	return certs[0], nil
}

// extractDomain picks the best domain identifier from the certificate.
// Prefers the first SAN DNS name, falls back to CN.
func extractDomain(cert *x509.Certificate) string {
	var raw string
	if len(cert.DNSNames) > 0 {
		raw = cert.DNSNames[0]
	} else {
		raw = cert.Subject.CommonName
	}
	return SanitizeDomain(raw)
}

// nonAlphanumDot matches characters that are not alphanumeric, dot, or hyphen.
var nonAlphanumDot = regexp.MustCompile(`[^a-zA-Z0-9.\-]`)

// SanitizeDomain converts a domain name into a safe MikroTik identifier.
// Strips wildcards, replaces unsafe characters with hyphens, trims edges.
func SanitizeDomain(domain string) string {
	// Strip wildcard prefix
	domain = strings.TrimPrefix(domain, "*.")

	// Replace unsafe characters
	domain = nonAlphanumDot.ReplaceAllString(domain, "-")

	// Trim leading/trailing hyphens and dots
	domain = strings.Trim(domain, "-.")

	if domain == "" {
		return "unknown"
	}
	return domain
}

// SplitPEMChain splits a PEM bundle into the leaf certificate and remaining
// chain certificates (intermediates). The leaf is the first non-CA certificate;
// if no explicit non-CA cert is found, the first cert is treated as the leaf.
func SplitPEMChain(certPEM []byte) (leaf []byte, chain [][]byte) {
	var blocks []*pem.Block
	remaining := certPEM
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
	}

	if len(blocks) == 0 {
		return certPEM, nil
	}

	leaf = pem.EncodeToMemory(blocks[0])
	for _, b := range blocks[1:] {
		chain = append(chain, pem.EncodeToMemory(b))
	}
	return leaf, chain
}

// ParseCommonName extracts the Subject CN from a single PEM-encoded certificate.
// Returns empty string if the PEM cannot be parsed.
func ParseCommonName(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return c.Subject.CommonName
}

// computeHash returns the hex-encoded SHA-256 digest of cert+key bytes.
func computeHash(certPEM, keyPEM []byte) string {
	h := sha256.New()
	h.Write(certPEM)
	h.Write(keyPEM)
	return fmt.Sprintf("%x", h.Sum(nil))
}
