// Package tunnelendpoint owns the syntax shared by every server persistence
// writer for a managed tunnel endpoint identity.
package tunnelendpoint

import (
	"errors"
	"regexp"
)

var canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ValidateUUID accepts only lowercase, hyphenated UUID text suitable for a
// DNS label. It intentionally does not accept braces, URN syntax, or compact
// UUID text because the value is persisted and emitted as a hostname label.
func ValidateUUID(value string) error {
	if !canonicalUUIDPattern.MatchString(value) {
		return errors.New("must be a canonical lowercase UUID")
	}
	return nil
}
