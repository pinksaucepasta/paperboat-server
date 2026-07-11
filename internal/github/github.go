package github

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
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
	ListRepos(context.Context, string) ([]Repo, error)
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

func (s Status) normalized() Status {
	if s.Scopes == nil {
		s.Scopes = []string{}
	}
	if s.MissingScopes == nil {
		s.MissingScopes = []string{}
	}
	return s
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
		return "", ErrClientNotConfigured
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
		return Status{Connected: false, Scopes: token.Scopes, MissingScopes: missing}.normalized(), ErrMissingScopes
	}
	ghUser, err := s.client.CurrentUser(ctx, token.AccessToken)
	if err != nil {
		return Status{}, err
	}
	accessCiphertext, err := secrets.Encrypt(s.cfg.Secrets.EncryptionKey, token.AccessToken)
	if err != nil {
		return Status{}, err
	}
	var refreshCiphertext []byte
	if token.RefreshToken != "" {
		refreshCiphertext, err = secrets.Encrypt(s.cfg.Secrets.EncryptionKey, token.RefreshToken)
		if err != nil {
			return Status{}, err
		}
	}
	var expiresAt sql.NullTime
	if !token.ExpiresAt.IsZero() {
		expiresAt = sql.NullTime{Time: token.ExpiresAt, Valid: true}
	}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		linkedUserID, err := q.LinkGitHubIdentity(ctx, dbsqlc.LinkGitHubIdentityParams{ID: newID("uid"), UserID: userID, ProviderSubject: ghUser.Login})
		if err != nil {
			return err
		}
		if linkedUserID != userID {
			return ErrIdentityLinkedToAnotherUser
		}
		err = q.UpsertGitHubOAuthToken(ctx, dbsqlc.UpsertGitHubOAuthTokenParams{ID: newID("ght"), UserID: userID, TokenCiphertext: accessCiphertext, RefreshTokenCiphertext: refreshCiphertext, Scopes: token.Scopes, ExpiresAt: expiresAt, ProviderAccountLogin: ghUser.Login})
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
	connection, err := s.db.Queries().GetGitHubConnectionStatus(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return status.normalized(), nil
	}
	if err != nil {
		return Status{}, err
	}
	status.Connected = true
	status.Scopes = connection.Scopes
	status.LastValidatedAt = connection.LastValidatedAt.Time
	status.MissingScopes = missingScopes(connection.Scopes, s.cfg.GitHub.OAuthScopes)
	repo, err := s.db.Queries().GetGitHubConfigRepoStatus(ctx, userID)
	if err == nil {
		status.ConfigRepoOwner, status.ConfigRepoName, status.ConfigRepoBranch = repo.Owner, repo.Name, repo.DefaultBranch
		status.ConfigRepoProvisioned = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Status{}, err
	}
	return status.normalized(), nil
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
	return secrets.Encrypt(s.cfg.Secrets.EncryptionKey, token)
}

func (s *Service) EnsureConnected(ctx context.Context, userID string) error {
	scopes, err := s.db.Queries().GetGitHubScopes(ctx, userID)
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

// ListRepos returns the repositories the connected GitHub account can access,
// most-recently-updated first, for selection during project creation.
func (s *Service) ListRepos(ctx context.Context, userID string) ([]Repo, error) {
	token, _, err := s.githubToken(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.client.ListRepos(ctx, token)
}

func (s *Service) githubToken(ctx context.Context, userID string) (string, string, error) {
	row, err := s.db.Queries().GetGitHubToken(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotConnected
	}
	if err != nil {
		return "", "", err
	}
	if missing := missingScopes(row.Scopes, s.cfg.GitHub.OAuthScopes); len(missing) > 0 {
		return "", "", ErrMissingScopes
	}
	token, err := secrets.Decrypt(s.cfg.Secrets.EncryptionKey, row.TokenCiphertext)
	return token, row.ProviderAccountLogin, err
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
		return tx.Queries().UpsertGitHubProvisioningAttempt(ctx, dbsqlc.UpsertGitHubProvisioningAttemptParams{ID: newID("ghp"), UserID: userID, IdempotencyKey: idempotencyKey, State: state, RepoOwner: owner, RepoName: name, LastError: lastErr})
	})
}

func (s *Service) storeRepo(ctx context.Context, userID, idempotencyKey string, repo Repo) error {
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		err := q.UpsertGitHubConfigRepository(ctx, dbsqlc.UpsertGitHubConfigRepositoryParams{ID: newID("ghr"), UserID: userID, ProviderRepoID: repo.ID, Owner: repo.Owner, Name: repo.Name, DefaultBranch: repo.DefaultBranch, CloneUrl: repo.CloneURL, HtmlUrl: repo.HTMLURL, Private: repo.Private})
		if err != nil {
			return err
		}
		if err := q.MarkGitHubProvisioningSucceeded(ctx, idempotencyKey); err != nil {
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

// listReposMaxPages bounds how many pages of the authenticated user's
// repositories are fetched (100 per page) so a very large account cannot make
// the request unbounded.
const listReposMaxPages = 10

func (c HTTPClient) ListRepos(ctx context.Context, token string) ([]Repo, error) {
	repos := make([]Repo, 0, 100)
	for page := 1; page <= listReposMaxPages; page++ {
		var body []githubRepoResponse
		path := fmt.Sprintf("/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member&page=%d", page)
		if err := c.doJSON(ctx, token, http.MethodGet, path, nil, &body); err != nil {
			return nil, err
		}
		for _, item := range body {
			repos = append(repos, item.repo())
		}
		if len(body) < 100 {
			break
		}
	}
	return repos, nil
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

func (f *FakeClient) ListRepos(context.Context, string) ([]Repo, error) {
	repos := make([]Repo, 0, len(f.Repos))
	for _, repo := range f.Repos {
		repos = append(repos, repo)
	}
	slices.SortFunc(repos, func(a, b Repo) int {
		return strings.Compare(a.Owner+"/"+a.Name, b.Owner+"/"+b.Name)
	})
	return repos, nil
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
	ErrClientNotConfigured         = errors.New("github client is not configured")
	ErrNotConnected                = errors.New("github connection required")
	ErrMissingScopes               = errors.New("github oauth token is missing required scopes")
	ErrIdentityLinkedToAnotherUser = errors.New("github identity is already linked to another user")
	ErrRepoNotFound                = errors.New("github repository not found")
	ErrFileNotFound                = errors.New("github file not found")
	ErrIdempotencyKeyRequired      = errors.New("idempotency key is required")
)
