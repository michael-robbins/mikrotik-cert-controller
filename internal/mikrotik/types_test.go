package mikrotik

import "testing"

func TestParseCertList(t *testing.T) {
	output := ` 0 K T name=example.com_0 common-name=example.com fingerprint=abc123
 1   T name=example.com_1 common-name=example.com fingerprint=def456
 2 K   name=other.com_0 common-name=other.com fingerprint=ghi789
 3       name=noflag.com_0 common-name=noflag.com fingerprint=jkl012
`

	entries := ParseCertList(output)
	if len(entries) != 4 {
		t.Fatalf("ParseCertList() returned %d entries, want 4", len(entries))
	}

	// First entry: has K and T flags
	if entries[0].Name != "example.com_0" {
		t.Errorf("entries[0].Name = %q, want %q", entries[0].Name, "example.com_0")
	}
	if !entries[0].PrivateKey {
		t.Error("entries[0].PrivateKey = false, want true")
	}
	if !entries[0].Trusted {
		t.Error("entries[0].Trusted = false, want true")
	}

	// Second entry: T flag only
	if entries[1].PrivateKey {
		t.Error("entries[1].PrivateKey = true, want false")
	}

	// Third entry: K flag only
	if entries[2].Trusted {
		t.Error("entries[2].Trusted = true, want false")
	}

	// Fourth entry: no flags at all
	if entries[3].Name != "noflag.com_0" {
		t.Errorf("entries[3].Name = %q, want %q", entries[3].Name, "noflag.com_0")
	}
	if entries[3].PrivateKey {
		t.Error("entries[3].PrivateKey = true, want false")
	}
	if entries[3].Trusted {
		t.Error("entries[3].Trusted = true, want false")
	}
}

func TestParseCertList_RouterOS7Detail(t *testing.T) {
	// Real RouterOS 7.22 /certificate print detail output with quoted values
	// and wider flag columns (K,L,C,A,I,R,E,T,a,D)
	output := `Flags: K - PRIVATE-KEY; L - CRL; C - SMART-CARD-KEY; A - AUTHORITY;
I - ISSUED, R - REVOKED; E - EXPIRED; T - TRUSTED; a - ACME-MANAGED;
D - DYNAMIC

41 KL    T   name="vpn.example.com.crt_0" trust-store=all digest-algorithm=sha256 trusted=yes common-name="vpn.example.com" subject-alt-name=DNS:vpn.example.com
34  L   T   name="Lets encrypt intermediate1_1762717761" trust-store=all
 0      T   name="isgrootx1" trust-store=all common-name="ISRG Root X1"
`

	entries := ParseCertList(output)
	if len(entries) != 3 {
		t.Fatalf("ParseCertList() returned %d entries, want 3", len(entries))
	}

	if entries[0].Name != "vpn.example.com.crt_0" {
		t.Errorf("entries[0].Name = %q, want %q", entries[0].Name, "vpn.example.com.crt_0")
	}
	if !entries[0].PrivateKey {
		t.Error("entries[0].PrivateKey = false, want true")
	}
	if !entries[0].Trusted {
		t.Error("entries[0].Trusted = false, want true")
	}
	if entries[0].CommonName != "vpn.example.com" {
		t.Errorf("entries[0].CommonName = %q, want %q", entries[0].CommonName, "vpn.example.com")
	}

	if entries[1].Name != "Lets encrypt intermediate1_1762717761" {
		t.Errorf("entries[1].Name = %q, want %q", entries[1].Name, "Lets encrypt intermediate1_1762717761")
	}

	if entries[2].Name != "isgrootx1" {
		t.Errorf("entries[2].Name = %q, want %q", entries[2].Name, "isgrootx1")
	}
}

func TestParseCertList_Empty(t *testing.T) {
	entries := ParseCertList("")
	if len(entries) != 0 {
		t.Errorf("ParseCertList(\"\") returned %d entries, want 0", len(entries))
	}
}

func TestFindCertsByDomain(t *testing.T) {
	entries := []CertEntry{
		{Name: "example.com_0"},
		{Name: "example.com_1"},
		{Name: "example.com.au_0"},
		{Name: "other.com_0"},
	}

	matched := FindCertsByDomain(entries, "example.com")
	if len(matched) != 2 {
		t.Errorf("FindCertsByDomain(\"example.com\") returned %d, want 2", len(matched))
	}

	// Verify it does not match example.com.au
	matchedAU := FindCertsByDomain(entries, "example.com.au")
	if len(matchedAU) != 1 {
		t.Errorf("FindCertsByDomain(\"example.com.au\") returned %d, want 1", len(matchedAU))
	}

	// Exact name match (no underscore suffix)
	entries = append(entries, CertEntry{Name: "exact.com"})
	matchedExact := FindCertsByDomain(entries, "exact.com")
	if len(matchedExact) != 1 {
		t.Errorf("FindCertsByDomain(\"exact.com\") returned %d, want 1", len(matchedExact))
	}

	// .crt_ naming convention (MikroTik uses uploaded filename as cert name prefix)
	entries = append(entries, CertEntry{Name: "vpn.example.com.crt_0", PrivateKey: true})
	matchedCrt := FindCertsByDomain(entries, "vpn.example.com")
	if len(matchedCrt) != 1 {
		t.Errorf("FindCertsByDomain(\"vpn.example.com\") with .crt_ name returned %d, want 1", len(matchedCrt))
	}
}
