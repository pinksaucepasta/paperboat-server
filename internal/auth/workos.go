package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/observability"
)

type FakeWorkOSVerifier struct{}

func (FakeWorkOSVerifier) VerifyCallback(_ context.Context, input CallbackInput) (WorkOSProfile, error) {
	if strings.TrimSpace(input.Code) == "" {
		return WorkOSProfile{}, errors.New("workos callback code is required")
	}
	parts := strings.Split(input.Code, ":")
	if len(parts) >= 2 {
		return WorkOSProfile{
			Subject:     strings.TrimSpace(parts[0]),
			Email:       strings.TrimSpace(parts[1]),
			DisplayName: strings.TrimSpace(strings.Join(parts[2:], ":")),
		}, nil
	}
	return WorkOSProfile{
		Subject:     "workos_" + input.Code,
		Email:       input.Code + "@example.invalid",
		DisplayName: input.Code,
	}, nil
}

type HTTPWorkOSVerifier struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

func (v HTTPWorkOSVerifier) VerifyCallback(ctx context.Context, input CallbackInput) (WorkOSProfile, error) {
	if strings.TrimSpace(v.BaseURL) == "" || strings.TrimSpace(v.ClientID) == "" || strings.TrimSpace(v.ClientSecret) == "" {
		return WorkOSProfile{}, errors.New("workos base url, client id, and client secret are required")
	}
	client := v.HTTPClient
	if client == nil {
		client = observability.DefaultProviderClient("workos")
	}
	payload := map[string]string{
		"client_id":     v.ClientID,
		"client_secret": v.ClientSecret,
		"code":          input.Code,
		"grant_type":    "authorization_code",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return WorkOSProfile{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(v.BaseURL, "/")+"/user_management/authenticate", bytes.NewReader(body))
	if err != nil {
		return WorkOSProfile{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return WorkOSProfile{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return WorkOSProfile{}, errors.New("workos callback verification failed")
	}
	var response struct {
		User struct {
			ID        string `json:"id"`
			Subject   string `json:"subject"`
			Email     string `json:"email"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Name      string `json:"name"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return WorkOSProfile{}, err
	}
	subject := response.User.Subject
	if subject == "" {
		subject = response.User.ID
	}
	name := strings.TrimSpace(response.User.Name)
	if name == "" {
		name = strings.TrimSpace(response.User.FirstName + " " + response.User.LastName)
	}
	return WorkOSProfile{Subject: subject, Email: response.User.Email, DisplayName: name}, nil
}
