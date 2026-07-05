package github

import (
	"errors"
	"net/http"
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
