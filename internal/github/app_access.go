package github

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	gh "github.com/google/go-github/v88/github"
)

var (
	ErrRepositoryAccessUnavailable = errors.New("repository-scoped access is unavailable")
	ErrRepositoryAccessInvalid     = errors.New("repository-scoped access response is invalid")
)

type RepositoryAccess struct {
	Token     string
	ExpiresAt time.Time
}

type RepositoryAccessBroker interface {
	ResolveInstallation(context.Context, string, string) (string, error)
	Issue(context.Context, string, string, string) (RepositoryAccess, error)
	Revoke(context.Context, string) error
}

type FakeRepositoryAccessBroker struct {
	Clock func() time.Time
}

func (b FakeRepositoryAccessBroker) ResolveInstallation(_ context.Context, _, repositoryID string) (string, error) {
	if strings.TrimSpace(repositoryID) == "" {
		return "", ErrRepositoryAccessUnavailable
	}
	return "github-installation:1", nil
}

func (b FakeRepositoryAccessBroker) Issue(_ context.Context, authorizationRef, repositoryID, contentsPermission string) (RepositoryAccess, error) {
	if authorizationRef != "github-installation:1" || strings.TrimSpace(repositoryID) == "" ||
		(contentsPermission != "read" && contentsPermission != "write") {
		return RepositoryAccess{}, ErrRepositoryAccessUnavailable
	}
	now := time.Now().UTC()
	if b.Clock != nil {
		now = b.Clock().UTC()
	}
	return RepositoryAccess{Token: "github-installation-token-" + repositoryID, ExpiresAt: now.Add(time.Hour)}, nil
}

func (FakeRepositoryAccessBroker) Revoke(_ context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrRepositoryAccessUnavailable
	}
	return nil
}

type GitHubAppBrokerConfig struct {
	BaseURL       string
	AppID         string
	PrivateKeyPEM string
	Client        *http.Client
	Clock         func() time.Time
}

type GitHubAppBroker struct {
	baseURL       *url.URL
	appID         int64
	privateKeyPEM []byte
	client        *http.Client
	appsClient    *gh.Client
	clock         func() time.Time
}

func NewGitHubAppBroker(config GitHubAppBrokerConfig) (*GitHubAppBroker, error) {
	base, err := url.Parse(strings.TrimSpace(config.BaseURL))
	appID, appIDErr := strconv.ParseInt(strings.TrimSpace(config.AppID), 10, 64)
	if err != nil || base.Scheme != "https" || base.User != nil || base.Hostname() == "" ||
		base.RawQuery != "" || base.Fragment != "" || appIDErr != nil || appID < 1 {
		return nil, ErrRepositoryAccessUnavailable
	}
	if config.Client == nil || config.Client.Timeout <= 0 {
		return nil, ErrRepositoryAccessUnavailable
	}
	transport := config.Client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	appsTransport, err := ghinstallation.NewAppsTransport(transport, appID, []byte(config.PrivateKeyPEM))
	if err != nil {
		return nil, ErrRepositoryAccessUnavailable
	}
	appsHTTPClient := &http.Client{Transport: appsTransport, Timeout: config.Client.Timeout}
	appsClient, err := newGitHubSDKClient(appsHTTPClient, "", base)
	if err != nil {
		return nil, ErrRepositoryAccessUnavailable
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &GitHubAppBroker{
		baseURL: base, appID: appID, privateKeyPEM: []byte(config.PrivateKeyPEM),
		client: config.Client, appsClient: appsClient, clock: config.Clock,
	}, nil
}

func (b *GitHubAppBroker) ResolveInstallation(ctx context.Context, oauthToken, repositoryID string) (string, error) {
	if strings.TrimSpace(oauthToken) == "" || strings.TrimSpace(repositoryID) == "" {
		return "", ErrRepositoryAccessUnavailable
	}
	repositoryNumber, err := strconv.ParseInt(repositoryID, 10, 64)
	if err != nil || repositoryNumber < 1 {
		return "", ErrRepositoryAccessUnavailable
	}
	client, err := newGitHubSDKClient(b.client, oauthToken, b.baseURL)
	if err != nil {
		return "", ErrRepositoryAccessUnavailable
	}
	installations, response, err := client.Apps.ListUserInstallations(ctx, &gh.ListOptions{PerPage: 100})
	if err != nil || response == nil || response.NextPage != 0 || len(installations) > 100 {
		return "", ErrRepositoryAccessUnavailable
	}
	for _, installation := range installations {
		if installation == nil || installation.GetID() < 1 {
			continue
		}
		repositories, reposResponse, listErr := client.Apps.ListUserRepos(ctx, installation.GetID(), &gh.ListOptions{PerPage: 100})
		if listErr != nil {
			return "", ErrRepositoryAccessUnavailable
		}
		if reposResponse == nil || reposResponse.NextPage != 0 || repositories.GetTotalCount() > 100 || len(repositories.Repositories) > 100 {
			continue
		}
		for _, repository := range repositories.Repositories {
			if repository != nil && repository.GetID() == repositoryNumber {
				return "github-installation:" + strconv.FormatInt(installation.GetID(), 10), nil
			}
		}
	}
	return "", ErrRepositoryAccessUnavailable
}

func (b *GitHubAppBroker) Issue(ctx context.Context, authorizationRef, repositoryID, contentsPermission string) (RepositoryAccess, error) {
	const prefix = "github-installation:"
	if !strings.HasPrefix(authorizationRef, prefix) || strings.TrimSpace(repositoryID) == "" ||
		(contentsPermission != "read" && contentsPermission != "write") {
		return RepositoryAccess{}, ErrRepositoryAccessUnavailable
	}
	installationID, err := strconv.ParseInt(strings.TrimPrefix(authorizationRef, prefix), 10, 64)
	if err != nil || installationID < 1 {
		return RepositoryAccess{}, ErrRepositoryAccessUnavailable
	}
	repositoryNumber, err := strconv.ParseInt(repositoryID, 10, 64)
	if err != nil || repositoryNumber < 1 {
		return RepositoryAccess{}, ErrRepositoryAccessUnavailable
	}
	metadataPermission := "read"
	token, _, err := b.appsClient.Apps.CreateInstallationToken(ctx, installationID, &gh.InstallationTokenOptions{
		RepositoryIDs: []int64{repositoryNumber},
		Permissions: &gh.InstallationPermissions{
			Contents: &contentsPermission,
			Metadata: &metadataPermission,
		},
	})
	if err != nil || token == nil {
		return RepositoryAccess{}, ErrRepositoryAccessUnavailable
	}
	expiresAt := time.Time{}
	if token.ExpiresAt != nil {
		expiresAt = token.ExpiresAt.Time
	}
	now := b.clock().UTC()
	if token.GetToken() == "" || len(token.GetToken()) > 4096 || !expiresAt.After(now.Add(time.Minute)) ||
		expiresAt.After(now.Add(time.Hour+time.Minute)) || token.GetPermissions().GetContents() != contentsPermission ||
		len(token.Repositories) != 1 || token.Repositories[0].GetID() != repositoryNumber {
		return RepositoryAccess{}, ErrRepositoryAccessInvalid
	}
	return RepositoryAccess{Token: token.GetToken(), ExpiresAt: expiresAt.UTC()}, nil
}

func (b *GitHubAppBroker) Revoke(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrRepositoryAccessUnavailable
	}
	client, err := newGitHubSDKClient(b.client, token, b.baseURL)
	if err != nil {
		return ErrRepositoryAccessUnavailable
	}
	if _, err := client.Apps.RevokeInstallationToken(ctx); err != nil {
		return ErrRepositoryAccessUnavailable
	}
	return nil
}

func newGitHubSDKClient(httpClient *http.Client, token string, base *url.URL) (*gh.Client, error) {
	if httpClient == nil || base == nil {
		return nil, ErrRepositoryAccessUnavailable
	}
	options := []gh.ClientOptionsFunc{gh.WithHTTPClient(httpClient)}
	if token != "" {
		options = append(options, gh.WithAuthToken(token))
	}
	apiBase, err := url.Parse(strings.TrimRight(base.String(), "/") + "/")
	if err != nil {
		return nil, ErrRepositoryAccessUnavailable
	}
	baseURL := apiBase.String()
	options = append(options, gh.WithURLs(&baseURL, &baseURL))
	client, err := gh.NewClient(options...)
	if err != nil {
		return nil, ErrRepositoryAccessUnavailable
	}
	return client, nil
}
