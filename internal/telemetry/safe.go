package telemetry

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// RedactedValue is the only replacement used for secret-like values.
	RedactedValue = "[REDACTED]"

	maximumSummaryBytes  = 256
	maximumRepairBytes   = 256
	maximumMessageBytes  = 512
	maximumEventLogSize  = 4096
	maximumMetadataBytes = 1000
	maximumMetadataItems = 64
	maximumMetadataDepth = 8
)

type redactionRule struct {
	pattern     *regexp.Regexp
	replacement string
}

// These rules run at construction time.  Logs and events therefore remain
// safe even when a downstream sink is not trusted to redact correctly.
var safeStringRedactions = []redactionRule{
	{regexp.MustCompile(`(?is)-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----`), RedactedValue},
	{regexp.MustCompile(`(?im)^\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*.*$`), RedactedValue},
	{regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`), RedactedValue},
	{regexp.MustCompile(`(?i)("(?:authorization|proxy_authorization|cookie|set_cookie|token|access_token|refresh_token|password|passwd|secret|api_key|client_secret|private_key|credential|credential_ref|credential_reference|secret_ref|token_ref|signed_url)"\s*:\s*)"[^"]*"`), `${1}"` + RedactedValue + `"`},
	{regexp.MustCompile(`(?i)((?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|token|access[_-]?token|refresh[_-]?token|password|passwd|secret|api[_-]?key|client[_-]?secret|private[_-]?key|credential(?:[_-]?(?:ref|reference))?|secret[_-]?ref|token[_-]?ref|signed[_-]?url)\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`), `${1}` + RedactedValue},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), RedactedValue},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), RedactedValue},
	{regexp.MustCompile(`\bgh[opusr]_[A-Za-z0-9]{20,}\b`), RedactedValue},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), RedactedValue},
	{regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s]+`), RedactedValue},
	{regexp.MustCompile(`(?i)(?:/Users/|/home/|[A-Z]:\\Users\\)[^\s,;]+`), RedactedValue},
	{regexp.MustCompile(`\b(?:account|actor|assignment|certificate|connector|correlation|device|domain|edge|host|operation|request|route|session|tunnel)_[A-Za-z0-9_.:-]+\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`), RedactedValue},
}

// Redact returns a bounded, printable, secret-safe form of value.  It never
// returns an error, so it is safe for last-resort logging paths.
func Redact(value string) string {
	redacted, err := safeBoundedString(value, maximumMessageBytes, false)
	if err != nil {
		return RedactedValue
	}
	return redacted
}

// SafeString returns a validated, redacted and UTF-8-safe string no longer
// than maximum bytes.  It is intended for adapters that need a field-specific
// bound while keeping the same construction-time redaction policy.
func SafeString(value string, maximum int) (string, error) {
	return safeBoundedString(value, maximum, false)
}

func safeBoundedString(value string, maximum int, required bool) (string, error) {
	if maximum <= 0 || !utf8.ValidString(value) {
		return "", newError(ErrorInvalidString, "construct control-plane telemetry")
	}
	for _, rule := range safeStringRedactions {
		value = rule.pattern.ReplaceAllString(value, rule.replacement)
	}
	value = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if required && value == "" {
		return "", newError(ErrorInvalidString, "construct control-plane telemetry")
	}
	if len(value) > maximum {
		value = value[:maximum]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value, nil
}

// safeMetadataString is the value path for typed metadata. A value that is
// exactly an already-validated opaque identifier is safe to retain. Free-form
// text still goes through the complete redaction pipeline, including the
// generic identifier rule. This keeps useful correlation/resource metadata
// while preventing identifiers embedded in prose from becoming labels.
func safeMetadataString(value, key string) (string, error) {
	if value != "" && strings.HasSuffix(strings.ToLower(key), "_id") && validOpaqueMetadataID(value) {
		return value, nil
	}
	return safeBoundedString(value, maximumMetadataBytes, false)
}

func validOpaqueMetadataID(value string) bool {
	if !resourceIDPattern.MatchString(value) || strings.ContainsAny(value, "/?#@%\\\r\n\t ") {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"secret", "token", "password", "credential", "authorization", "cookie"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return strings.Contains(value, "_") || strings.Contains(value, "-")
}

// safeJSONNumber is kept separate so metadata can accept json.Number without
// allowing NaN, infinities, or arbitrary custom values through the interface.
func safeJSONNumber(value json.Number) (json.Number, error) {
	if value == "" {
		return "", newError(ErrorInvalidString, "construct safe metadata")
	}
	if _, err := value.Float64(); err != nil {
		return "", newError(ErrorInvalidString, "construct safe metadata")
	}
	return value, nil
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
