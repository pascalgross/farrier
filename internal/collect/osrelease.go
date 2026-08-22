package collect

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// OSReleasePath is where the distribution identifies itself.
//
// /etc/os-release is a symlink to /usr/lib/os-release on merged-usr systems, which all five supported
// releases are. Reading the /etc path works on both and is what the specification tells readers to do.
const OSReleasePath = "/etc/os-release"

// ParseOSRelease reads the os-release key-value format.
//
// The format is shell-like but is not shell, and it must never be evaluated as shell — some
// distributions ship values containing characters that would be meaningful to a shell, and "source
// /etc/os-release" is a pattern this project will not adopt. Quotes are stripped and everything else is
// taken literally.
func ParseOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("collect: reading %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	fields := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else {
			value = strings.Trim(value, `"'`)
		}
		fields[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("collect: reading %s: %w", path, err)
	}
	return fields, nil
}

// supportedUbuntu is the set of Ubuntu releases in standard support.
//
// The policy Farrier states is a rule — the Ubuntu LTS releases in standard support, plus Debian stable
// and oldstable — and this is that rule written down at a point in time. It needs revisiting when a
// release leaves standard support, which is why the reason is recorded here rather than only in the
// README: 20.04 is absent because it is ESM-only, not because it was forgotten.
var supportedUbuntu = map[string]bool{
	"jammy":    true, // 22.04
	"noble":    true, // 24.04
	"resolute": true, // 26.04
}

// supportedDebian is the set of Debian releases Farrier supports: stable and oldstable.
var supportedDebian = map[string]bool{
	"bookworm": true, // 12, oldstable
	"trixie":   true, // 13, stable
}

// DistributionFromOSRelease builds a Distribution from parsed os-release fields.
//
// It exists separately from the platform implementations so that both families derive identity the same
// way, and so that a test can assert the classification against real os-release contents from all five
// supported releases without needing those releases to hand.
func DistributionFromOSRelease(fields map[string]string) (Distribution, error) {
	id := strings.ToLower(fields["ID"])
	codename := strings.ToLower(fields["VERSION_CODENAME"])
	if codename == "" {
		codename = strings.ToLower(fields["UBUNTU_CODENAME"])
	}

	d := Distribution{
		ID:         id,
		Codename:   codename,
		Version:    fields["VERSION_ID"],
		PrettyName: fields["PRETTY_NAME"],
	}

	// ID_LIKE is consulted so that a derivative naming itself something else still lands on the right
	// implementation. A Debian derivative that reported as its own ID and got no platform at all would
	// be a host Farrier refused to look at, which helps nobody.
	like := strings.Fields(strings.ToLower(fields["ID_LIKE"]))
	switch {
	case id == "ubuntu":
		d.Family = FamilyUbuntu
		d.Supported = supportedUbuntu[codename]
	case id == "debian":
		d.Family = FamilyDebian
		d.Supported = supportedDebian[codename]
	case contains(like, "ubuntu"):
		d.Family = FamilyUbuntu
	case contains(like, "debian"):
		d.Family = FamilyDebian
	default:
		return d, fmt.Errorf("collect: %q is not an Ubuntu or Debian system (ID=%q ID_LIKE=%q)",
			d.PrettyName, id, fields["ID_LIKE"])
	}
	return d, nil
}

// contains reports whether a slice holds a value.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
