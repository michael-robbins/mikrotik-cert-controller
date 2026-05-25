package mikrotik

import "testing"

func TestImportCert(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		passphrase string
		want       string
	}{
		{
			name:     "no passphrase",
			filename: "example.com.crt",
			want:     `/certificate import file-name="example.com.crt" passphrase=""`,
		},
		{
			name:       "with passphrase",
			filename:   "example.com.crt",
			passphrase: "secret",
			want:       `/certificate import file-name="example.com.crt" passphrase="secret"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ImportCert(tt.filename, tt.passphrase)
			if got != tt.want {
				t.Errorf("ImportCert() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetWWWSSLCert(t *testing.T) {
	got := SetWWWSSLCert("example.com_0")
	want := `/ip service set www-ssl certificate="example.com_0"`
	if got != want {
		t.Errorf("SetWWWSSLCert() = %q, want %q", got, want)
	}
}

func TestSetIPsecPeerCert(t *testing.T) {
	got := SetIPsecPeerCert("my-peer", "example.com_0")
	want := `/ip ipsec peer set "my-peer" certificate="example.com_0"`
	if got != want {
		t.Errorf("SetIPsecPeerCert() = %q, want %q", got, want)
	}
}
