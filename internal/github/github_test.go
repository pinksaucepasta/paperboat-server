package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
