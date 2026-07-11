package agentunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

const papercodeResponseLimit = 1 << 20

type PapercodeCredentialIssuer struct {
	Issuer       string
	Signer       *mint.Provider
	HTTPClient   *http.Client
	RequireHTTPS bool
	ProofTTL     time.Duration
}

func (p *PapercodeCredentialIssuer) CheckCLI(_ context.Context, input CredentialInput) error {
	if p == nil || p.Signer == nil || strings.TrimSpace(p.Issuer) == "" {
		return errors.New("papercode mint signer is not configured")
	}
	if strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.ClientSessionID) == "" {
		return errors.New("papercode credential input is incomplete")
	}
	return nil
}

func (p *PapercodeCredentialIssuer) CheckHealth(ctx context.Context, input CredentialInput) error {
	if err := p.CheckCLI(ctx, input); err != nil {
		return err
	}
	base, err := p.validateBaseURL(input.HTTPBaseURL)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	ttl := p.ProofTTL
	if ttl <= 0 || ttl > mint.MaxProofTTL {
		ttl = mint.MaxProofTTL
	}
	jti, err := randomOpaqueID("jti")
	if err != nil {
		return err
	}
	nonce, err := randomOpaqueID("nonce")
	if err != nil {
		return err
	}
	proof, err := p.Signer.SignHealth(mint.ProofInput{
		Issuer: p.Issuer, EnvironmentID: input.EnvironmentID, UserID: input.UserID,
		ClientSessionID: input.ClientSessionID, JTI: jti, Nonce: nonce,
		IssuedAt: now, ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"proof": proof})
	if err != nil {
		return err
	}
	var response struct {
		Status        string `json:"status"`
		EnvironmentID string `json:"environmentId"`
	}
	if err := p.requestJSON(ctx, http.MethodPost, base+"/api/paperboat/health", "application/json", body, "", &response); err != nil {
		return err
	}
	if response.Status != "ready" || response.EnvironmentID != input.EnvironmentID {
		return errors.New("papercode returned invalid health readiness")
	}
	return nil
}

func (p *PapercodeCredentialIssuer) IssueCLI(ctx context.Context, input CredentialInput) (CLICredentials, error) {
	if err := p.CheckCLI(ctx, input); err != nil {
		return CLICredentials{}, err
	}
	base, err := p.validateBaseURL(input.HTTPBaseURL)
	if err != nil {
		return CLICredentials{}, err
	}
	terminal, err := p.issueAccess(ctx, base, input, "terminal:operate")
	if err != nil {
		cleanupErr := p.cleanupIssued(ctx, input, []papercodeAccess{terminal}, "issuance_failed")
		return failedCleanupCredentials(cleanupErr, terminal), errors.Join(fmt.Errorf("issue terminal credential: %w", err), cleanupErr)
	}
	file, err := p.issueAccess(ctx, base, input, "file:stage")
	if err != nil {
		cleanupErr := p.cleanupIssued(ctx, input, []papercodeAccess{terminal, file}, "issuance_failed")
		return failedCleanupCredentials(cleanupErr, terminal, file), errors.Join(fmt.Errorf("issue file credential: %w", err), cleanupErr)
	}
	var ticket struct {
		Ticket    string    `json:"ticket"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := p.requestJSON(ctx, http.MethodPost, base+"/api/auth/websocket-ticket", "application/json", nil, terminal.AccessToken, &ticket); err != nil {
		cleanupErr := p.cleanupIssued(ctx, input, []papercodeAccess{terminal, file}, "ticket_failed")
		return failedCleanupCredentials(cleanupErr, terminal, file), errors.Join(fmt.Errorf("request websocket ticket: %w", err), cleanupErr)
	}
	if ticket.Ticket == "" || ticket.ExpiresAt.IsZero() {
		cleanupErr := p.cleanupIssued(ctx, input, []papercodeAccess{terminal, file}, "ticket_invalid")
		return failedCleanupCredentials(cleanupErr, terminal, file), errors.Join(errors.New("papercode returned an invalid websocket ticket"), cleanupErr)
	}
	return CLICredentials{
		TerminalAuth:      map[string]any{"method": "websocket_ticket", "ticket": ticket.Ticket, "expires_at": ticket.ExpiresAt, "scopes": []string{"terminal:operate"}},
		UploadAuth:        map[string]any{"method": "bearer", "token": file.AccessToken, "expires_at": file.ExpiresAt, "scopes": []string{"file:stage"}},
		TerminalSessionID: terminal.SessionID,
		FileSessionID:     file.SessionID,
	}, nil
}

func failedCleanupCredentials(cleanupErr error, accesses ...papercodeAccess) CLICredentials {
	if cleanupErr == nil {
		return CLICredentials{}
	}
	credentials := CLICredentials{}
	if len(accesses) > 0 {
		credentials.TerminalSessionID = accesses[0].SessionID
	}
	if len(accesses) > 1 {
		credentials.FileSessionID = accesses[1].SessionID
	}
	return credentials
}

func (p *PapercodeCredentialIssuer) cleanupIssued(ctx context.Context, input CredentialInput, accesses []papercodeAccess, reason string) error {
	sessionIDs := make([]string, 0, len(accesses))
	for _, access := range accesses {
		if access.SessionID != "" {
			sessionIDs = append(sessionIDs, access.SessionID)
		}
	}
	if len(sessionIDs) == 0 {
		return nil
	}
	return p.RevokeCLI(ctx, CredentialRevocationInput{
		UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.EnvironmentID,
		ClientSessionID: input.ClientSessionID, HTTPBaseURL: input.HTTPBaseURL,
		SessionIDs: sessionIDs, Reason: reason,
	})
}

func (p *PapercodeCredentialIssuer) RevokeCLI(ctx context.Context, input CredentialRevocationInput) error {
	base, err := p.validateBaseURL(input.HTTPBaseURL)
	if err != nil {
		return err
	}
	if p == nil || p.Signer == nil || strings.TrimSpace(p.Issuer) == "" || strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.ClientSessionID) == "" || strings.TrimSpace(input.Reason) == "" || len(input.SessionIDs) == 0 {
		return errors.New("papercode revocation input is incomplete")
	}
	now := time.Now().UTC()
	ttl := p.ProofTTL
	if ttl <= 0 || ttl > mint.MaxProofTTL {
		ttl = mint.MaxProofTTL
	}
	jti, err := randomOpaqueID("jti")
	if err != nil {
		return err
	}
	nonce, err := randomOpaqueID("nonce")
	if err != nil {
		return err
	}
	proof, err := p.Signer.SignRevocation(mint.RevocationInput{
		ProofInput: mint.ProofInput{
			Issuer: p.Issuer, EnvironmentID: input.EnvironmentID, UserID: input.UserID,
			ClientSessionID: input.ClientSessionID, JTI: jti, Nonce: nonce,
			IssuedAt: now, ExpiresAt: now.Add(ttl),
		},
		SessionIDs: input.SessionIDs,
		Reason:     input.Reason,
	})
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"proof": proof})
	if err != nil {
		return err
	}
	var response struct {
		RevokedSessionIDs []string `json:"revokedSessionIds"`
	}
	if err := p.requestJSON(ctx, http.MethodPost, base+"/api/paperboat/revoke-sessions", "application/json", body, "", &response); err != nil {
		return err
	}
	revoked := make(map[string]struct{}, len(response.RevokedSessionIDs))
	for _, sessionID := range response.RevokedSessionIDs {
		revoked[sessionID] = struct{}{}
	}
	for _, sessionID := range input.SessionIDs {
		if _, ok := revoked[sessionID]; !ok {
			return fmt.Errorf("papercode did not confirm revocation of session %q", sessionID)
		}
	}
	return nil
}

type papercodeAccess struct {
	AccessToken string
	SessionID   string
	ExpiresAt   time.Time
}

func (p *PapercodeCredentialIssuer) issueAccess(ctx context.Context, base string, input CredentialInput, scope string) (papercodeAccess, error) {
	now := time.Now().UTC()
	remainingSeconds := int64(input.ExpiresAt.Sub(now) / time.Second)
	if remainingSeconds <= 0 {
		return papercodeAccess{}, errors.New("connect descriptor expires too soon to issue papercode access")
	}
	ttl := p.ProofTTL
	if ttl <= 0 || ttl > mint.MaxProofTTL {
		ttl = mint.MaxProofTTL
	}
	jti, err := randomOpaqueID("jti")
	if err != nil {
		return papercodeAccess{}, err
	}
	nonce, err := randomOpaqueID("nonce")
	if err != nil {
		return papercodeAccess{}, err
	}
	proof, err := p.Signer.Sign(mint.ProofInput{
		Issuer: p.Issuer, EnvironmentID: input.EnvironmentID, UserID: input.UserID,
		ClientSessionID: input.ClientSessionID, JTI: jti, Nonce: nonce,
		IssuedAt: now, ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return papercodeAccess{}, err
	}
	mintBody, err := json.Marshal(map[string]string{"proof": proof})
	if err != nil {
		return papercodeAccess{}, err
	}
	var minted struct {
		Credential string `json:"credential"`
	}
	if err := p.requestJSON(ctx, http.MethodPost, base+"/api/paperboat/mint-credential", "application/json", mintBody, "", &minted); err != nil {
		return papercodeAccess{}, err
	}
	if minted.Credential == "" {
		return papercodeAccess{}, errors.New("papercode returned an empty bootstrap credential")
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {minted.Credential},
		"subject_token_type":   {"urn:t3:params:oauth:token-type:environment-bootstrap"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":                {scope},
		"expires_in":           {strconv.FormatInt(remainingSeconds, 10)},
		"client_label":         {"Paperboat CLI"},
		"client_device_type":   {"bot"},
		"client_os":            {"paperboat"},
	}
	var token struct {
		AccessToken string `json:"access_token"`
		SessionID   string `json:"session_id"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := p.requestJSON(ctx, http.MethodPost, base+"/oauth/token", "application/x-www-form-urlencoded", []byte(form.Encode()), "", &token); err != nil {
		return papercodeAccess{}, err
	}
	if token.AccessToken == "" || token.SessionID == "" || token.TokenType != "Bearer" || token.Scope != scope || token.ExpiresIn <= 0 {
		return papercodeAccess{SessionID: token.SessionID}, errors.New("papercode returned an invalid scoped bearer session")
	}
	if token.ExpiresIn > remainingSeconds {
		return papercodeAccess{SessionID: token.SessionID}, errors.New("papercode bearer session exceeds connect descriptor lifetime")
	}
	expiresAt := now.Add(time.Duration(token.ExpiresIn) * time.Second)
	if expiresAt.After(input.ExpiresAt) {
		expiresAt = input.ExpiresAt
	}
	return papercodeAccess{AccessToken: token.AccessToken, SessionID: token.SessionID, ExpiresAt: expiresAt}, nil
}

func (p *PapercodeCredentialIssuer) requestJSON(ctx context.Context, method, endpoint, contentType string, body []byte, bearer string, target any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, papercodeResponseLimit))
		return fmt.Errorf("papercode returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, papercodeResponseLimit)).Decode(target); err != nil {
		return fmt.Errorf("decode papercode response: %w", err)
	}
	return nil
}

func (p *PapercodeCredentialIssuer) validateBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("papercode base URL is invalid")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && !p.RequireHTTPS) {
		return "", errors.New("papercode base URL must use HTTPS")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func randomOpaqueID(prefix string) (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate %s: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}
