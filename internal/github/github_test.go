package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

func TestGitHubAppAuthorizationDoesNotRequestClassicOAuthScopes(t *testing.T) {
	cfg := config.Default()
	cfg.Secrets.GitHubClientID = "client-id"
	cfg.GitHub.AppID = "123"
	cfg.Secrets.GitHubAppPrivateKey = "configured"
	service := NewService(nil, nil, nil, cfg)

	authorizationURL, err := service.OAuthAuthorizeURL("state", "https://app.example.test/github/callback")
	if err != nil {
		t.Fatalf("OAuthAuthorizeURL: %v", err)
	}
	if strings.Contains(authorizationURL, "scope=") {
		t.Fatalf("GitHub App authorization requested classic OAuth scopes: %s", authorizationURL)
	}
	if missing := missingScopes(nil, service.requiredOAuthScopes()); len(missing) != 0 {
		t.Fatalf("GitHub App token unexpectedly requires classic scopes: %v", missing)
	}
}

func TestAlreadyExistsValidationOnlyMatchesSpecificGitHubError(t *testing.T) {
	err := APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    "Validation Failed",
		Errors: []APIErrorDetail{{
			Code: "already_exists",
		}},
	}
	if !isAlreadyExistsValidation(err) {
		t.Fatal("expected already_exists validation to be ignored")
	}
}

func TestGitHubOutcomeUncertainClassification(t *testing.T) {
	if !githubOutcomeUncertain(context.DeadlineExceeded) {
		t.Fatal("network timeout must be outcome-unknown")
	}
	if !githubOutcomeUncertain(APIError{StatusCode: http.StatusBadGateway}) {
		t.Fatal("5xx response must be outcome-unknown")
	}
	if githubOutcomeUncertain(APIError{StatusCode: http.StatusUnprocessableEntity}) {
		t.Fatal("validation response must be definitive")
	}
}

func TestAlreadyExistsValidationDoesNotHideOther422Errors(t *testing.T) {
	err := APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    "Validation Failed",
		Errors: []APIErrorDetail{{
			Code:    "invalid",
			Message: "branch does not exist",
		}},
	}
	if isAlreadyExistsValidation(err) {
		t.Fatal("invalid validation error was incorrectly ignored")
	}
	if isAlreadyExistsValidation(errors.New("github api request failed: status 422")) {
		t.Fatal("plain 422 error string was incorrectly ignored")
	}
}

func TestHTTPClientListReposPaginates(t *testing.T) {
	page1 := make([]map[string]any, 100)
	for i := range page1 {
		page1[i] = map[string]any{"id": i, "name": "repo", "default_branch": "main", "clone_url": "https://github.com/o/repo.git", "owner": map[string]any{"login": "o"}}
	}
	var gotPages []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/repos" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("per_page") != "100" || q.Get("sort") != "updated" {
			t.Fatalf("unexpected query %q", r.URL.RawQuery)
		}
		gotPages = append(gotPages, q.Get("page"))
		w.Header().Set("Content-Type", "application/json")
		switch q.Get("page") {
		case "1":
			w.Header().Set("Link", `<`+srv.URL+`/user/repos?page=2&per_page=100&sort=updated>; rel="next"`)
			_ = json.NewEncoder(w).Encode(page1)
		case "2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 999, "name": "last", "default_branch": "dev", "clone_url": "https://github.com/o/last.git", "owner": map[string]any{"login": "o"}}})
		default:
			t.Fatalf("unexpected page %q", q.Get("page"))
		}
	}))
	defer srv.Close()

	client := HTTPClient{BaseURL: srv.URL}
	repos, err := client.ListRepos(context.Background(), "tok")
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 101 {
		t.Fatalf("repos = %d, want 101", len(repos))
	}
	if len(gotPages) != 2 || gotPages[0] != "1" || gotPages[1] != "2" {
		t.Fatalf("requested pages = %v", gotPages)
	}
	if repos[100].Name != "last" || repos[100].DefaultBranch != "dev" {
		t.Fatalf("last repo = %+v", repos[100])
	}
}

func TestHTTPClientListReposPreservesRepositoryIDExactly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1310688414,"name":"config","default_branch":"main","clone_url":"https://github.com/o/config.git","private":true,"owner":{"login":"o"}}]`))
	}))
	defer srv.Close()

	repos, err := (HTTPClient{BaseURL: srv.URL}).ListRepos(context.Background(), "tok")
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 1 || repos[0].ID != "1310688414" {
		t.Fatalf("repository ID = %q, want exact decimal provider ID", repos[0].ID)
	}
}

func TestFakeClientListReposSorted(t *testing.T) {
	fake := &FakeClient{Repos: map[string]Repo{
		"o/beta":  {Owner: "o", Name: "beta"},
		"o/alpha": {Owner: "o", Name: "alpha"},
	}}
	repos, err := fake.ListRepos(context.Background(), "tok")
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 2 || repos[0].Name != "alpha" || repos[1].Name != "beta" {
		t.Fatalf("repos = %+v", repos)
	}
}
