package config

import (
	"encoding/json"
	"strings"
)

func (c Config) RedactedJSON() string {
	redacted := c
	redacted.Secrets.SessionKeys = redactSlice(redacted.Secrets.SessionKeys)
	redacted.Secrets.EncryptionKey = redact(redacted.Secrets.EncryptionKey)
	redacted.Secrets.WorkOSAPIKey = redact(redacted.Secrets.WorkOSAPIKey)
	redacted.Secrets.WorkOSClientID = redact(redacted.Secrets.WorkOSClientID)
	redacted.Secrets.WorkOSClientSecret = redact(redacted.Secrets.WorkOSClientSecret)
	redacted.Secrets.PolarAPIKey = redact(redacted.Secrets.PolarAPIKey)
	redacted.Secrets.PolarWebhookSecret = redact(redacted.Secrets.PolarWebhookSecret)
	redacted.Secrets.GitHubClientID = redact(redacted.Secrets.GitHubClientID)
	redacted.Secrets.GitHubClientSecret = redact(redacted.Secrets.GitHubClientSecret)
	redacted.Secrets.FlyAPIToken = redact(redacted.Secrets.FlyAPIToken)
	b, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func redactSlice(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = redact(value)
	}
	return out
}

func redact(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "[redacted]"
	}
	return value[:4] + strings.Repeat("*", 8) + value[len(value)-4:]
}
