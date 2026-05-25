package mikrotik

import (
	"regexp"
	"strings"
)

// CertEntry represents a parsed certificate from RouterOS /certificate print output.
type CertEntry struct {
	Name        string
	CommonName  string
	Fingerprint string
	PrivateKey  bool // has "K" flag
	Trusted     bool // has "T" flag
}

// certLineRegex matches certificate entries from RouterOS /certificate print detail output.
// RouterOS 7.x has up to 10 flag positions (K,L,C,A,I,R,E,T,a,D) and quotes values.
// Names may contain spaces when quoted (e.g. "Lets encrypt intermediate1_1762717761").
var certLineRegex = regexp.MustCompile(`^\s*\d+\s+([A-Za-z\s]*?)\s*name=(?:"([^"]+)"|(\S+))`)

// ParseCertList parses the output of /certificate print detail.
func ParseCertList(output string) []CertEntry {
	var entries []CertEntry

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		matches := certLineRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		flags := matches[1]
		name := matches[2]
		if name == "" {
			name = matches[3]
		}

		entry := CertEntry{
			Name:       name,
			PrivateKey: strings.Contains(flags, "K"),
			Trusted:    strings.Contains(flags, "T"),
		}

		// Extract common-name if present (may be quoted in RouterOS 7.x)
		if idx := strings.Index(line, "common-name="); idx != -1 {
			cn := line[idx+len("common-name="):]
			if len(cn) > 0 && cn[0] == '"' {
				cn = cn[1:]
				if end := strings.IndexByte(cn, '"'); end != -1 {
					cn = cn[:end]
				}
			} else if spaceIdx := strings.IndexByte(cn, ' '); spaceIdx != -1 {
				cn = cn[:spaceIdx]
			}
			entry.CommonName = cn
		}

		entries = append(entries, entry)
	}

	return entries
}

// FindCertsByDomain returns certificates whose name matches the given domain.
// MikroTik names imported certificates based on the uploaded filename plus a
// sequence suffix: "filename_0", "filename_1", etc. Since the upload uses
// "domain.crt", the resulting cert name is "domain.crt_0". We match both
// "domain_*" and "domain.crt_*" to handle either naming convention.
func FindCertsByDomain(entries []CertEntry, domain string) []CertEntry {
	var matched []CertEntry
	for _, e := range entries {
		if e.Name == domain ||
			strings.HasPrefix(e.Name, domain+"_") ||
			strings.HasPrefix(e.Name, domain+".crt_") ||
			strings.HasPrefix(e.Name, domain+".chain-") {
			matched = append(matched, e)
		}
	}
	return matched
}
