package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, cn string, sans []string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func generateTestCA(t *testing.T, cn string) (certDER []byte, key *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return certDER, key
}

func generateLeafSignedByCA(t *testing.T, caCertDER []byte, caKey *ecdsa.PrivateKey, cn string, sans []string) (certDER []byte, keyPEM []byte) {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              sans,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certDER, err = x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	return certDER, keyPEM
}

func TestParse(t *testing.T) {
	tests := []struct {
		name       string
		cn         string
		sans       []string
		wantDomain string
		wantErr    bool
	}{
		{
			name:       "SAN preferred over CN",
			cn:         "fallback.example.com",
			sans:       []string{"primary.example.com", "secondary.example.com"},
			wantDomain: "primary.example.com",
		},
		{
			name:       "CN used when no SANs",
			cn:         "only-cn.example.com",
			sans:       nil,
			wantDomain: "only-cn.example.com",
		},
		{
			name:       "wildcard stripped",
			cn:         "*.example.com",
			sans:       []string{"*.example.com"},
			wantDomain: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			certPEM, keyPEM := generateTestCert(t, tt.cn, tt.sans)

			info, err := Parse(certPEM, keyPEM)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if info.DomainName != tt.wantDomain {
				t.Errorf("DomainName = %q, want %q", info.DomainName, tt.wantDomain)
			}
			if info.Hash == "" {
				t.Error("Hash is empty")
			}
			if info.NotAfter.IsZero() {
				t.Error("NotAfter is zero")
			}
		})
	}
}

func TestParse_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		cert    []byte
		key     []byte
		wantErr string
	}{
		{
			name:    "invalid cert PEM",
			cert:    []byte("not a pem"),
			key:     []byte("not a pem"),
			wantErr: "decode cert PEM",
		},
		{
			name: "invalid key PEM",
			cert: func() []byte {
				c, _ := generateTestCert(t, "test.com", nil)
				return c
			}(),
			key:     []byte("not a pem"),
			wantErr: "decode key PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tt.cert, tt.key)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := err.Error(); !contains(got, tt.wantErr) {
				t.Errorf("error = %q, want containing %q", got, tt.wantErr)
			}
		})
	}
}

func TestSanitizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"*.example.com", "example.com"},
		{"sub.example.com", "sub.example.com"},
		{"weird chars!@#.com", "weird-chars---.com"},
		{"", "unknown"},
		{"*.", "unknown"},
		{"---", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := SanitizeDomain(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParse_StableHash(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "test.com", nil)

	info1, err := Parse(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	info2, err := Parse(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	if info1.Hash != info2.Hash {
		t.Errorf("hash not stable: %q != %q", info1.Hash, info2.Hash)
	}
}

func TestParse_PicksLeafFromChain(t *testing.T) {
	caDER, caKey := generateTestCA(t, "Test CA")
	leafDER, keyPEM := generateLeafSignedByCA(t, caDER, caKey, "leaf-cn.example.com", []string{"leaf-san.example.com"})

	// Put CA first to ensure parser doesn't blindly take the first cert.
	chainPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...,
	)

	info, err := Parse(chainPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if info.DomainName != "leaf-san.example.com" {
		t.Fatalf("DomainName = %q, want %q", info.DomainName, "leaf-san.example.com")
	}
}

func TestParseCommonName(t *testing.T) {
	certPEM, _ := generateTestCert(t, "R13", nil)
	cn := ParseCommonName(certPEM)
	if cn != "R13" {
		t.Errorf("ParseCommonName() = %q, want %q", cn, "R13")
	}

	if got := ParseCommonName([]byte("not pem")); got != "" {
		t.Errorf("ParseCommonName(invalid) = %q, want empty", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
