package github

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	Scopes       []string
	ExpiresAt    time.Time
}

type Client interface {
	ExchangeOAuthCode(context.Context, OAuthExchangeInput) (OAuthToken, error)
	CurrentUser(context.Context, string) (GitHubUser, error)
	GetRepo(context.Context, string, string, string) (Repo, error)
	CreateRepo(context.Context, string, RepoCreateInput) (Repo, error)
	GetFile(context.Context, string, string, string, string, string) (File, error)
	PutFile(context.Context, string, string, string, PutFileInput) error
}

type OAuthExchangeInput struct {
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
}

type GitHubUser struct {
	Login string
}

type Repo struct {
	ID            string
	Owner         string
	Name          string
	DefaultBranch string
	CloneURL      string
	HTMLURL       string
	Private       bool
}

type RepoCreateInput struct {
	Name          string
	Private       bool
	AutoInit      bool
	DefaultBranch string
}

type PutFileInput struct {
	Path    string
	Message string
	Content []byte
	Branch  string
}

type File struct {
	Path string
	SHA  string
}

type Status struct {
	Connected             bool      `json:"connected"`
	Scopes                []string  `json:"scopes"`
	MissingScopes         []string  `json:"missing_scopes"`
	LastValidatedAt       time.Time `json:"last_validated_at,omitempty"`
	ConfigRepoProvisioned bool      `json:"config_repo_provisioned"`
	ConfigRepoOwner       string    `json:"config_repo_owner,omitempty"`
	ConfigRepoName        string    `json:"config_repo_name,omitempty"`
	ConfigRepoBranch      string    `json:"config_repo_branch,omitempty"`
}

type ConfigRepo struct {
	ID            string `json:"id"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	CloneURL      string `json:"clone_url"`
	HTMLURL       string `json:"html_url"`
	Private       bool   `json:"private"`
}

type Service struct {
	db     *db.DB
	audit  *audit.Writer
	client Client
	cfg    config.Config
	now    func() time.Time
}

func NewService(store *db.DB, auditWriter *audit.Writer, client Client, cfg config.Config) *Service {
	return &Service{db: store, audit: auditWriter, client: client, cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) DefaultCallbackURL() string {
	return strings.TrimRight(s.cfg.HTTP.PublicBaseURL, "/") + "/api/github/oauth/callback"
}

func (s *Service) OAuthAuthorizeURL(state, redirectURI string) (string, error) {
	if strings.TrimSpace(s.cfg.Secrets.GitHubClientID) == "" && !s.cfg.Providers.FakeMode {
		return "", errors.New("github client id is not configured")
	}
	if strings.TrimSpace(redirectURI) == "" {
		redirectURI = s.DefaultCallbackURL()
	}
	u, err := url.Parse(s.cfg.GitHub.OAuthAuthorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", s.cfg.Secrets.GitHubClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("scope", strings.Join(s.cfg.GitHub.OAuthScopes, " "))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Service) CompleteOAuth(ctx context.Context, userID, code, redirectURI string) (Status, error) {
	if s.client == nil {
		return Status{}, errors.New("github client is not configured")
	}
	token, err := s.client.ExchangeOAuthCode(ctx, OAuthExchangeInput{
		Code:         code,
		RedirectURI:  redirectURI,
		ClientID:     s.cfg.Secrets.GitHubClientID,
		ClientSecret: s.cfg.Secrets.GitHubClientSecret,
	})
	if err != nil {
		return Status{}, err
	}
	missing := missingScopes(token.Scopes, s.cfg.GitHub.OAuthScopes)
	if len(missing) > 0 {
		return Status{Connected: false, Scopes: token.Scopes, MissingScopes: missing}, ErrMissingScopes
	}
	ghUser, err := s.client.CurrentUser(ctx, token.AccessToken)
	if err != nil {
		return Status{}, err
	}
	accessCiphertext, err := encrypt(s.cfg.Secrets.EncryptionKey, token.AccessToken)
	if err != nil {
		return Status{}, err
	}
	var refreshCiphertext []byte
	if token.RefreshToken != "" {
		refreshCiphertext, err = encrypt(s.cfg.Secrets.EncryptionKey, token.RefreshToken)
		if err != nil {
			return Status{}, err
		}
	}
	var expiresAt any
	if !token.ExpiresAt.IsZero() {
		expiresAt = token.ExpiresAt
	}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var linkedUserID string
		err := tx.QueryRow(ctx, `
INSERT INTO user_identities (id, user_id, provider, provider_subject, email, created_at, updated_at)
VALUES ($1, $2, 'github', $3, '', now(), now())
ON CONFLICT (provider, provider_subject) DO UPDATE SET updated_at = now()
RETURNING user_id`,
			newID("uid"), userID, ghUser.Login).Scan(&linkedUserID)
		if err != nil {
			return err
		}
		if linkedUserID != userID {
			return ErrIdentityLinkedToAnotherUser
		}
		_, err = tx.Exec(ctx, `
INSERT INTO github_oauth_tokens
	(id, user_id, token_ciphertext, refresh_token_ciphertext, scopes, expires_at, provider_account_login, last_validated_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now(), now())
ON CONFLICT (user_id) DO UPDATE SET
	token_ciphertext = EXCLUDED.token_ciphertext,
	refresh_token_ciphertext = EXCLUDED.refresh_token_ciphertext,
	scopes = EXCLUDED.scopes,
	expires_at = EXCLUDED.expires_at,
	provider_account_login = EXCLUDED.provider_account_login,
	revoked_at = NULL,
	last_validated_at = now(),
	updated_at = now(),
	version = github_oauth_tokens.version + 1`,
			newID("ght"), userID, accessCiphertext, refreshCiphertext, token.Scopes, expiresAt, ghUser.Login)
		if err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{
			ActorUserID: userID, ActorType: audit.ActorUser, EventType: "github.oauth.connected",
			ResourceType: "user", ResourceID: userID, IdempotencyKey: "github.oauth.connected:" + userID + ":" + ghUser.Login,
			Metadata: map[string]any{"provider": "github", "scopes": token.Scopes},
		})
	})
	if err != nil {
		return Status{}, err
	}
	return s.Status(ctx, userID)
}

func (s *Service) Status(ctx context.Context, userID string) (Status, error) {
	var status Status
	var scopes []string
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT scopes, last_validated_at
FROM paperboat.github_oauth_tokens
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY updated_at DESC
LIMIT 1`, userID).Scan((*stringArray)(&scopes), &status.LastValidatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return Status{}, err
	}
	status.Connected = true
	status.Scopes = scopes
	status.MissingScopes = missingScopes(scopes, s.cfg.GitHub.OAuthScopes)
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT owner, name, default_branch
FROM paperboat.github_config_repositories
WHERE user_id = $1 AND provisioned_at IS NOT NULL`, userID)
	if err := row.Scan(&status.ConfigRepoOwner, &status.ConfigRepoName, &status.ConfigRepoBranch); err == nil {
		status.ConfigRepoProvisioned = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Status{}, err
	}
	return status, nil
}

func (s *Service) ProvisionConfigRepo(ctx context.Context, userID, idempotencyKey string) (ConfigRepo, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return ConfigRepo{}, ErrIdempotencyKeyRequired
	}
	accessToken, owner, err := s.githubToken(ctx, userID)
	if err != nil {
		return ConfigRepo{}, err
	}
	if s.client == nil {
		return ConfigRepo{}, errors.New("github client is not configured")
	}
	repoName := s.cfg.GitHub.ConfigRepoName
	branch := s.cfg.GitHub.ConfigRepoBranch
	if err := s.recordAttempt(ctx, userID, idempotencyKey, "started", owner, repoName, ""); err != nil {
		return ConfigRepo{}, err
	}
	repo, err := s.client.GetRepo(ctx, accessToken, owner, repoName)
	if errors.Is(err, ErrRepoNotFound) {
		repo, err = s.client.CreateRepo(ctx, accessToken, RepoCreateInput{Name: repoName, Private: true, AutoInit: true, DefaultBranch: branch})
	}
	if err != nil {
		_ = s.recordAttempt(ctx, userID, idempotencyKey, "retryable_failed", owner, repoName, err.Error())
		return ConfigRepo{}, err
	}
	if !repo.Private {
		err := errors.New("github config repository is not private")
		_ = s.recordAttempt(ctx, userID, idempotencyKey, "failed", owner, repoName, err.Error())
		return ConfigRepo{}, err
	}
	if repo.DefaultBranch == "" {
		repo.DefaultBranch = branch
	}
	if err := s.initializeRepo(ctx, accessToken, repo); err != nil {
		_ = s.recordAttempt(ctx, userID, idempotencyKey, "retryable_failed", owner, repoName, err.Error())
		return ConfigRepo{}, err
	}
	if err := s.storeRepo(ctx, userID, idempotencyKey, repo); err != nil {
		return ConfigRepo{}, err
	}
	return ConfigRepo{ID: repo.ID, Owner: repo.Owner, Name: repo.Name, DefaultBranch: repo.DefaultBranch, CloneURL: repo.CloneURL, HTMLURL: repo.HTMLURL, Private: repo.Private}, nil
}

func (s *Service) CredentialForConfigSync(ctx context.Context, userID string) ([]byte, error) {
	token, _, err := s.githubToken(ctx, userID)
	if err != nil {
		return nil, err
	}
	return encrypt(s.cfg.Secrets.EncryptionKey, token)
}

func (s *Service) EnsureConnected(ctx context.Context, userID string) error {
	var scopes []string
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT scopes
FROM paperboat.github_oauth_tokens
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY updated_at DESC
LIMIT 1`, userID).Scan((*stringArray)(&scopes))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotConnected
	}
	if err != nil {
		return err
	}
	if missing := missingScopes(scopes, s.cfg.GitHub.OAuthScopes); len(missing) > 0 {
		return ErrMissingScopes
	}
	return nil
}

func (s *Service) githubToken(ctx context.Context, userID string) (string, string, error) {
	var ciphertext []byte
	var login string
	var scopes []string
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT token_ciphertext, provider_account_login, scopes
FROM paperboat.github_oauth_tokens
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY updated_at DESC
LIMIT 1`, userID).Scan(&ciphertext, &login, (*stringArray)(&scopes))
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotConnected
	}
	if err != nil {
		return "", "", err
	}
	if missing := missingScopes(scopes, s.cfg.GitHub.OAuthScopes); len(missing) > 0 {
		return "", "", ErrMissingScopes
	}
	token, err := decrypt(s.cfg.Secrets.EncryptionKey, ciphertext)
	return token, login, err
}

func (s *Service) initializeRepo(ctx context.Context, token string, repo Repo) error {
	files := map[string][]byte{
		"README.md":                       []byte("# Paperboat Config\n\nThis private repository stores portable Paperboat VM configuration.\n"),
		".paperboat/preview-url-skill.md": []byte("# Preview URLs\n\nWhen an app starts on localhost inside a Paperboat VM, surface the Paperboat preview URL instead of a raw localhost URL.\n"),
		".paperboat/config-sync.json":     []byte("{\n  \"version\": 1,\n  \"managed_by\": \"paperboat\"\n}\n"),
	}
	for path, content := range files {
		if _, err := s.client.GetFile(ctx, token, repo.Owner, repo.Name, path, repo.DefaultBranch); err == nil {
			continue
		} else if !errors.Is(err, ErrFileNotFound) {
			return err
		}
		if err := s.client.PutFile(ctx, token, repo.Owner, repo.Name, PutFileInput{
			Path: path, Message: "Initialize Paperboat config", Content: content, Branch: repo.DefaultBranch,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) recordAttempt(ctx context.Context, userID, idempotencyKey, state, owner, name, lastErr string) error {
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO github_repo_provisioning_attempts (id, user_id, idempotency_key, state, repo_owner, repo_name, last_error, attempts, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 1, now(), now())
ON CONFLICT (idempotency_key) DO UPDATE SET
	state = EXCLUDED.state,
	repo_owner = EXCLUDED.repo_owner,
	repo_name = EXCLUDED.repo_name,
	last_error = EXCLUDED.last_error,
	attempts = github_repo_provisioning_attempts.attempts + 1,
	updated_at = now()`, newID("ghp"), userID, idempotencyKey, state, owner, name, lastErr)
		return err
	})
}

func (s *Service) storeRepo(ctx context.Context, userID, idempotencyKey string, repo Repo) error {
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO github_config_repositories (id, user_id, provider_repo_id, owner, name, default_branch, clone_url, html_url, private, provisioned_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now(), now())
ON CONFLICT (user_id) DO UPDATE SET
	provider_repo_id = EXCLUDED.provider_repo_id,
	owner = EXCLUDED.owner,
	name = EXCLUDED.name,
	default_branch = EXCLUDED.default_branch,
	clone_url = EXCLUDED.clone_url,
	html_url = EXCLUDED.html_url,
	private = EXCLUDED.private,
	provisioned_at = now(),
	updated_at = now(),
	version = github_config_repositories.version + 1`,
			newID("ghr"), userID, repo.ID, repo.Owner, repo.Name, repo.DefaultBranch, repo.CloneURL, repo.HTMLURL, repo.Private)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE github_repo_provisioning_attempts SET state = 'succeeded', updated_at = now() WHERE idempotency_key = $1`, idempotencyKey); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{
			ActorUserID: userID, ActorType: audit.ActorUser, EventType: "github.config_repo.provisioned",
			ResourceType: "github_config_repository", ResourceID: repo.Owner + "/" + repo.Name,
			IdempotencyKey: "github.config_repo.provisioned:" + userID + ":" + repo.Owner + "/" + repo.Name,
			Metadata:       map[string]any{"provider": "github", "private": repo.Private, "default_branch": repo.DefaultBranch},
		})
	})
}

type HTTPClient struct {
	BaseURL  string
	TokenURL string
	Client   *http.Client
}

func (c HTTPClient) ExchangeOAuthCode(ctx context.Context, input OAuthExchangeInput) (OAuthToken, error) {
	form := url.Values{}
	form.Set("client_id", input.ClientID)
	form.Set("client_secret", input.ClientSecret)
	form.Set("code", input.Code)
	form.Set("redirect_uri", input.RedirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return OAuthToken{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return OAuthToken{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return OAuthToken{}, errors.New("github oauth exchange failed")
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return OAuthToken{}, err
	}
	token := OAuthToken{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken, Scopes: splitScopes(body.Scope)}
	if body.ExpiresIn > 0 {
		token.ExpiresAt = time.Now().UTC().Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	return token, nil
}

func (c HTTPClient) CurrentUser(ctx context.Context, token string) (GitHubUser, error) {
	var body struct {
		Login string `json:"login"`
	}
	if err := c.doJSON(ctx, token, http.MethodGet, "/user", nil, &body); err != nil {
		return GitHubUser{}, err
	}
	return GitHubUser{Login: body.Login}, nil
}

func (c HTTPClient) GetRepo(ctx context.Context, token, owner, name string) (Repo, error) {
	var body githubRepoResponse
	err := c.doJSON(ctx, token, http.MethodGet, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), nil, &body)
	if errors.Is(err, ErrRepoNotFound) {
		return Repo{}, err
	}
	return body.repo(), err
}

func (c HTTPClient) CreateRepo(ctx context.Context, token string, input RepoCreateInput) (Repo, error) {
	payload := map[string]any{"name": input.Name, "private": input.Private, "auto_init": input.AutoInit}
	var body githubRepoResponse
	if err := c.doJSON(ctx, token, http.MethodPost, "/user/repos", payload, &body); err != nil {
		return Repo{}, err
	}
	repo := body.repo()
	if repo.DefaultBranch == "" {
		repo.DefaultBranch = input.DefaultBranch
	}
	return repo, nil
}

func (c HTTPClient) GetFile(ctx context.Context, token, owner, name, path, branch string) (File, error) {
	requestPath := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/contents/" + escapePath(path)
	if branch != "" {
		requestPath += "?ref=" + url.QueryEscape(branch)
	}
	var body struct {
		Path string `json:"path"`
		SHA  string `json:"sha"`
		Type string `json:"type"`
	}
	err := c.doJSON(ctx, token, http.MethodGet, requestPath, nil, &body)
	if errors.Is(err, ErrRepoNotFound) {
		return File{}, ErrFileNotFound
	}
	if err != nil {
		return File{}, err
	}
	if body.Type != "" && body.Type != "file" {
		return File{}, fmt.Errorf("github path %q exists but is not a file", path)
	}
	return File{Path: body.Path, SHA: body.SHA}, nil
}

func (c HTTPClient) PutFile(ctx context.Context, token, owner, name string, input PutFileInput) error {
	payload := map[string]any{"message": input.Message, "content": base64Encode(input.Content), "branch": input.Branch}
	err := c.doJSON(ctx, token, http.MethodPut, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/contents/"+escapePath(input.Path), payload, nil)
	if isAlreadyExistsValidation(err) {
		return nil
	}
	return err
}

func (c HTTPClient) doJSON(ctx context.Context, token, method, path string, payload any, target any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return ErrRepoNotFound
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return parseGitHubAPIError(res)
	}
	if target != nil {
		return json.NewDecoder(res.Body).Decode(target)
	}
	return nil
}

type APIError struct {
	StatusCode int
	Message    string
	Errors     []APIErrorDetail
}

func (e APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("github api request failed: status %d", e.StatusCode)
	}
	return fmt.Sprintf("github api request failed: status %d: %s", e.StatusCode, e.Message)
}

type APIErrorDetail struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

func parseGitHubAPIError(res *http.Response) error {
	var payload struct {
		Message string           `json:"message"`
		Errors  []APIErrorDetail `json:"errors"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&payload)
	return APIError{StatusCode: res.StatusCode, Message: payload.Message, Errors: payload.Errors}
}

func isAlreadyExistsValidation(err error) bool {
	var apiErr APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnprocessableEntity {
		return false
	}
	for _, detail := range apiErr.Errors {
		if detail.Code == "already_exists" || strings.Contains(strings.ToLower(detail.Message), "already exists") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(apiErr.Message), "already exists")
}

func (c HTTPClient) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}

type githubRepoResponse struct {
	ID            any    `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	CloneURL      string `json:"clone_url"`
	HTMLURL       string `json:"html_url"`
	Private       bool   `json:"private"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (r githubRepoResponse) repo() Repo {
	return Repo{ID: fmt.Sprint(r.ID), Owner: r.Owner.Login, Name: r.Name, DefaultBranch: r.DefaultBranch, CloneURL: r.CloneURL, HTMLURL: r.HTMLURL, Private: r.Private}
}

type FakeClient struct {
	Token       OAuthToken
	User        GitHubUser
	Repos       map[string]Repo
	Created     int
	PutFiles    []string
	ExchangeErr error
	CreateErr   error
}

func (f *FakeClient) ExchangeOAuthCode(_ context.Context, input OAuthExchangeInput) (OAuthToken, error) {
	if f.ExchangeErr != nil {
		return OAuthToken{}, f.ExchangeErr
	}
	if strings.TrimSpace(input.Code) == "" {
		return OAuthToken{}, errors.New("github oauth code is required")
	}
	if f.Token.AccessToken != "" {
		return f.Token, nil
	}
	return OAuthToken{AccessToken: "fake-gh-token", Scopes: []string{"repo"}}, nil
}

func (f *FakeClient) CurrentUser(context.Context, string) (GitHubUser, error) {
	if f.User.Login != "" {
		return f.User, nil
	}
	return GitHubUser{Login: "paperboat-test-user"}, nil
}

func (f *FakeClient) GetRepo(_ context.Context, _, owner, name string) (Repo, error) {
	if f.Repos == nil {
		f.Repos = map[string]Repo{}
	}
	repo, ok := f.Repos[owner+"/"+name]
	if !ok {
		return Repo{}, ErrRepoNotFound
	}
	return repo, nil
}

func (f *FakeClient) CreateRepo(_ context.Context, _ string, input RepoCreateInput) (Repo, error) {
	if f.CreateErr != nil {
		return Repo{}, f.CreateErr
	}
	if f.Repos == nil {
		f.Repos = map[string]Repo{}
	}
	f.Created++
	owner := f.User.Login
	if owner == "" {
		owner = "paperboat-test-user"
	}
	repo := Repo{ID: "fake-repo-id", Owner: owner, Name: input.Name, DefaultBranch: input.DefaultBranch, CloneURL: "https://github.com/" + owner + "/" + input.Name + ".git", HTMLURL: "https://github.com/" + owner + "/" + input.Name, Private: input.Private}
	f.Repos[owner+"/"+input.Name] = repo
	return repo, nil
}

func (f *FakeClient) GetFile(_ context.Context, _, owner, name, path, _ string) (File, error) {
	key := owner + "/" + name + "/" + path
	for _, existing := range f.PutFiles {
		if existing == key {
			return File{Path: path, SHA: "fake-sha"}, nil
		}
	}
	return File{}, ErrFileNotFound
}

func (f *FakeClient) PutFile(_ context.Context, _, owner, name string, input PutFileInput) error {
	f.PutFiles = append(f.PutFiles, owner+"/"+name+"/"+input.Path)
	return nil
}

func missingScopes(have, required []string) []string {
	var missing []string
	for _, scope := range required {
		scope = strings.TrimSpace(scope)
		if scope != "" && !slices.Contains(have, scope) {
			missing = append(missing, scope)
		}
	}
	return missing
}

func splitScopes(raw string) []string {
	raw = strings.ReplaceAll(raw, ",", " ")
	fields := strings.Fields(raw)
	if fields == nil {
		return []string{}
	}
	return fields
}

func encrypt(key string, plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, errors.New("cannot encrypt empty secret")
	}
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, []byte(plaintext), nil)...), nil
}

func decrypt(key string, ciphertext []byte) (string, error) {
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, encrypted := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func base64Encode(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(b) == 0 {
		return ""
	}
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		value := uint(chunk[0])<<16 | uint(chunk[1])<<8 | uint(chunk[2])
		out.WriteByte(alphabet[(value>>18)&63])
		out.WriteByte(alphabet[(value>>12)&63])
		if n > 1 {
			out.WriteByte(alphabet[(value>>6)&63])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(alphabet[value&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

func escapePath(path string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

type stringArray []string

func (a *stringArray) Scan(src any) error {
	switch v := src.(type) {
	case string:
		*a = parsePgTextArray(v)
	case []byte:
		*a = parsePgTextArray(string(v))
	default:
		return fmt.Errorf("unsupported text array source %T", src)
	}
	return nil
}

func parsePgTextArray(raw string) []string {
	raw = strings.Trim(raw, "{}")
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.Trim(parts[i], `"`)
	}
	return parts
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

var (
	ErrNotConnected                = errors.New("github connection required")
	ErrMissingScopes               = errors.New("github oauth token is missing required scopes")
	ErrIdentityLinkedToAnotherUser = errors.New("github identity is already linked to another user")
	ErrRepoNotFound                = errors.New("github repository not found")
	ErrFileNotFound                = errors.New("github file not found")
	ErrIdempotencyKeyRequired      = errors.New("idempotency key is required")
)
