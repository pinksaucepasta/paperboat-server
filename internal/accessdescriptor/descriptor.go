// Package accessdescriptor defines the provider-neutral CLI connection contract.
package accessdescriptor

import "time"

const SchemaV1 = "paperboat.environment-connection/v1"

const (
	EnvironmentHosted = "hosted"
	EnvironmentBYOD   = "byod"

	CapabilityTerminal = "terminal"
	CapabilityHerdr    = "herdr"
	CapabilityUpload   = "upload"
	CapabilityPreview  = "preview"
	CapabilityActivity = "activity"
)

type Descriptor struct {
	Schema            string      `json:"schema"`
	Issuer            string      `json:"issuer"`
	Connectable       bool        `json:"connectable"`
	ExpiresAt         time.Time   `json:"expires_at"`
	Environment       Environment `json:"environment"`
	Helper            *Helper     `json:"helper,omitempty"`
	Capabilities      []string    `json:"capabilities,omitempty"`
	Terminal          *Terminal   `json:"terminal,omitempty"`
	Upload            *Upload     `json:"upload,omitempty"`
	Preview           *Preview    `json:"preview,omitempty"`
	Status            string      `json:"status"`
	Reason            string      `json:"reason"`
	RetryAfterSeconds int         `json:"retry_after_seconds"`
}

type Environment struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	ResourceID  string `json:"resource_id"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	Root        string `json:"root,omitempty"`
}

type Helper struct {
	ID         string `json:"id"`
	Generation int64  `json:"generation"`
}

type Auth struct {
	Method    string    `json:"method"`
	Ticket    string    `json:"ticket,omitempty"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    []string  `json:"scopes"`
}

type Terminal struct {
	Endpoint     string `json:"endpoint"`
	HTTPEndpoint string `json:"http_endpoint,omitempty"`
	Auth         Auth   `json:"auth"`
	SessionID    string `json:"session_id"`
	ThreadID     string `json:"thread_id"`
	TerminalID   string `json:"terminal_id"`
	CWD          string `json:"cwd"`
}

type Upload struct {
	Endpoint         string   `json:"endpoint"`
	Auth             Auth     `json:"auth"`
	MaxBytes         int64    `json:"max_bytes"`
	AllowedMIMETypes []string `json:"allowed_mime_types"`
	RetentionSeconds int64    `json:"retention_seconds"`
}

type Preview struct {
	Endpoint  string    `json:"endpoint"`
	Auth      Auth      `json:"auth"`
	ExpiresAt time.Time `json:"expires_at"`
	PublicURL string    `json:"public_url,omitempty"`
	State     string    `json:"state"`
}
