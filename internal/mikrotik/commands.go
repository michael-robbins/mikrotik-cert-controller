package mikrotik

import "fmt"

// ImportCert returns the RouterOS command to import a certificate file.
func ImportCert(filename, passphrase string) string {
	if passphrase != "" {
		return fmt.Sprintf("/certificate import file-name=%q passphrase=%q", filename, passphrase)
	}
	return fmt.Sprintf(`/certificate import file-name=%q passphrase=""`, filename)
}

// ImportKey returns the RouterOS command to import a key file.
func ImportKey(filename string) string {
	return fmt.Sprintf(`/certificate import file-name=%q passphrase=""`, filename)
}

// PrintCerts returns the RouterOS command to list certificates.
func PrintCerts() string {
	return "/certificate print detail without-paging"
}

// PrintCertByName returns the RouterOS command to find a certificate by name prefix.
func PrintCertByName(namePrefix string) string {
	return fmt.Sprintf("/certificate print detail without-paging where name~%q", "^"+namePrefix)
}

// PrintCertByCommonName returns the RouterOS command to find certificates by common-name.
func PrintCertByCommonName(cn string) string {
	return fmt.Sprintf("/certificate print detail without-paging where common-name=%q", cn)
}

// RemoveCert returns the RouterOS command to remove a certificate by name.
func RemoveCert(name string) string {
	return fmt.Sprintf("/certificate remove %q", name)
}

// RemoveFile returns the RouterOS command to delete a file.
func RemoveFile(filename string) string {
	return fmt.Sprintf("/file remove %q", filename)
}

// SetWWWSSLCert returns the RouterOS command to assign a cert to the www-ssl service.
func SetWWWSSLCert(certName string) string {
	return fmt.Sprintf("/ip service set www-ssl certificate=%q", certName)
}

// SetAPISSLCert returns the RouterOS command to assign a cert to the api-ssl service.
func SetAPISSLCert(certName string) string {
	return fmt.Sprintf("/ip service set api-ssl certificate=%q", certName)
}

// SetIPsecPeerCert returns the RouterOS command to assign a cert to an IPsec peer.
func SetIPsecPeerCert(peerName, certName string) string {
	return fmt.Sprintf("/ip ipsec peer set %q certificate=%q", peerName, certName)
}

// SetIPsecIdentityCert returns the RouterOS command to assign a cert to an IPsec identity.
func SetIPsecIdentityCert(identityName, certName string) string {
	return fmt.Sprintf("/ip ipsec identity set %q certificate=%q", identityName, certName)
}
