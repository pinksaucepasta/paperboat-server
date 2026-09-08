// Package teams owns current team membership and resource permissions. Encrypted
// ENV key custody remains in environment; a role never confers key possession.
package teams

import (
	"errors"
	"regexp"
	"time"
)

var (
	ErrInvalid   = errors.New("invalid team request")
	ErrForbidden = errors.New("team permission denied")
	ErrNotFound  = errors.New("team resource not found")
	ErrConflict  = errors.New("team changed; refresh and retry")
	ErrExpired   = errors.New("team invitation expired or already used")
	ErrLimit     = errors.New("team capacity reached")
)

const MaximumMembers = 128
const MaximumInvitations = 128
const MaximumResources = 128

// Exact stored-result/digest reconciliation covers the latest 4096 operations
// per account. Older requests still cannot repeat effects: team generations,
// permanent team IDs and single-use invitations reject stale requests. Clients
// refresh current team state after Conflict, Expired or NotFound.
const MaximumOperationReceipts = 4096
const MaximumReceiptBytes = 1024
const MaximumInvitationHistory = 4096
const MaximumCounter uint64 = 9007199254740991
const InvitationLifetime = 24 * time.Hour

type Member struct {
	AccountID            string `json:"account_id"`
	MembershipGeneration uint64 `json:"membership_generation"`
	Role                 string `json:"role"`
	Active               bool   `json:"active"`
}
type Grant struct {
	AccountID    string `json:"account_id"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
	Permission   string `json:"permission"`
	Generation   uint64 `json:"generation"`
	Active       bool   `json:"active"`
}
type Team struct {
	TeamID       string   `json:"team_id"`
	OwnerAccount string   `json:"owner_account"`
	Generation   uint64   `json:"generation"`
	Deleted      bool     `json:"deleted"`
	Members      []Member `json:"members"`
	Grants       []Grant  `json:"grants"`
}
type CreateRequest struct {
	OperationID string `json:"operation_id"`
	TeamID      string `json:"team_id"`
}
type MutationRequest struct {
	OperationID        string `json:"operation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Action             string `json:"action"`
	AccountID          string `json:"account_id"`
	Role               string `json:"role"`
	Confirmation       string `json:"confirmation"`
}
type InviteRequest struct {
	OperationID        string `json:"operation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	AccountID          string `json:"account_id"`
}
type AcceptRequest struct {
	OperationID string `json:"operation_id"`
}
type Invitation struct {
	InvitationID string    `json:"invitation_id"`
	TeamID       string    `json:"team_id"`
	AccountID    string    `json:"account_id"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
	Generation   uint64    `json:"generation"`
}
type GrantRequest struct {
	OperationID        string `json:"operation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	AccountID          string `json:"account_id"`
	ResourceKind       string `json:"resource_kind"`
	ResourceID         string `json:"resource_id"`
	Permission         string `json:"permission"`
	Active             bool   `json:"active"`
}
type AttachRequest struct {
	OperationID        string `json:"operation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	ResourceKind       string `json:"resource_kind"`
	ResourceID         string `json:"resource_id"`
	Active             bool   `json:"active"`
}
type Decision struct {
	TeamID               string `json:"team_id"`
	AccountID            string `json:"account_id"`
	Role                 string `json:"role"`
	TeamGeneration       uint64 `json:"team_generation"`
	MembershipGeneration uint64 `json:"membership_generation"`
	GrantGeneration      uint64 `json:"grant_generation"`
	BindingGeneration    uint64 `json:"binding_generation"`
	ResourceKind         string `json:"resource_kind"`
	ResourceID           string `json:"resource_id"`
	Permission           string `json:"permission"`
}

var identifierExpression = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func validID(s string) bool {
	return len(s) > 0 && len(s) <= 128 && identifierExpression.MatchString(s)
}

func member(t Team, account string) (Member, bool) {
	for _, m := range t.Members {
		if m.AccountID == account && m.Active {
			return m, true
		}
	}
	return Member{}, false
}
func administrative(role string) bool { return role == "owner" || role == "admin" }
func permits(kind, granted, wanted string) bool {
	if kind == "env" {
		return (wanted == "read" && (granted == "read" || granted == "write")) || (wanted == "write" && granted == "write")
	}
	return (kind == "preview" || kind == "tunnel" || kind == "lazy_policy") && ((wanted == "use" && (granted == "use" || granted == "manage")) || (wanted == "manage" && granted == "manage"))
}
