package teaminbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type HTTPReceiptSender struct {
	endpoint, token, from string
	client                *http.Client
}

func NewHTTPReceiptSender(endpoint, token, from string, client *http.Client) (*HTTPReceiptSender, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) || strings.TrimSpace(token) == "" || strings.TrimSpace(from) == "" || strings.ContainsAny(from, "\r\n\x00") {
		return nil, ErrInvalid
	}
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPReceiptSender{endpoint: u.String(), token: token, from: from, client: client}, nil
}

func (s *HTTPReceiptSender) SendReceipt(ctx context.Context, message ReceiptMessage) (string, error) {
	if message.IdempotencyKey == "" || message.To == "" || strings.ContainsAny(message.To, "\r\n\x00") || len(message.Subject) > 200 || len(message.Text) > 2048 {
		return "", ErrInvalid
	}
	payload, _ := json.Marshal(map[string]string{"from": s.from, "to": message.To, "subject": message.Subject, "text": message.Text})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+s.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", message.IdempotencyKey)
	response, err := s.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	if readErr != nil {
		return "", readErr
	}
	if len(body) > 4096 || response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errors.New("receipt email delivery failed")
	}
	var result struct {
		MessageID string `json:"message_id"`
	}
	if json.Unmarshal(body, &result) != nil || strings.TrimSpace(result.MessageID) == "" || len(result.MessageID) > 256 {
		return "", errors.New("receipt email response is invalid")
	}
	return result.MessageID, nil
}
