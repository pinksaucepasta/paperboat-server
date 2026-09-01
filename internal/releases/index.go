package releases

// ValidVersion reports whether value has the release-version shape accepted by
// the current release manifest and signed release-index contracts. The
// canonical validation rule lives in current.go; this exported wrapper keeps
// the shared server-side update validation on that single rule.
func ValidVersion(value string) bool { return validVersion(value) }
