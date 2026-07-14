package classifier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateCandidateRejectsUnsafeMetadata(t *testing.T) {
	for _, candidate := range []Candidate{
		{Path: "/etc/passwd", FileType: "file", LocationClass: "home"},
		{Path: "../secret", FileType: "file", LocationClass: "home"},
		{Path: ".config/tool", FileType: "socket", LocationClass: "xdg_config"},
	} {
		if err := validateCandidate(&candidate); err == nil {
			t.Fatalf("candidate %#v was accepted", candidate)
		}
	}
}

func TestProviderRequestContainsMetadataOnlyAndParsesStrictOutput(t *testing.T) {
	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		requestBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"results\":[{\"path\":\".config/tool/config.json\",\"decision\":\"portable\",\"confidence\":0.9,\"reason_code\":\"tool_config\"}]}"},"finish_reason":"stop","index":0}]}`)
	}))
	defer server.Close()
	service, err := New(Config{BaseURL: server.URL, APIKey: "test-key", Model: "test-model", Revision: "classifier-1", Timeout: time.Second, MaxCandidates: 4, SchemaMode: "json_schema"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := service.Classify(context.Background(), []Candidate{{Path: ".config/tool/config.json", FileType: "file", Size: 42, ChangeFrequency: "changed", LocationClass: "xdg_config", Siblings: []Sibling{{Name: "settings.json", FileType: "file"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 || response.Results[0].Decision != Portable {
		t.Fatalf("response=%#v", response)
	}
	for _, forbidden := range []string{"file_content", "absolute_path", "workspace_name", "credential-that-must-not-leak"} {
		if strings.Contains(requestBody, forbidden) {
			t.Fatalf("request leaked forbidden field %q: %s", forbidden, requestBody)
		}
	}
	if !strings.Contains(requestBody, "response_format") || !strings.Contains(requestBody, "untrusted_metadata") {
		t.Fatalf("request missing structured safety controls: %s", requestBody)
	}
}

func TestProviderRejectsMalformedAndInvalidEnumOutput(t *testing.T) {
	for _, content := range []string{`not-json`, `{"results":[{"path":".config/tool","decision":"copy_all","confidence":1,"reason_code":"bad"}]}`} {
		t.Run(content, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":`+strconv.Quote(content)+`},"finish_reason":"stop","index":0}]}`)
			}))
			defer server.Close()
			service, _ := New(Config{BaseURL: server.URL, APIKey: "key", Model: "model", Revision: "1", Timeout: time.Second, MaxCandidates: 1, SchemaMode: "json_object"})
			if _, err := service.Classify(context.Background(), []Candidate{{Path: ".config/tool", FileType: "file", LocationClass: "xdg_config"}}); err == nil {
				t.Fatal("invalid output was accepted")
			}
		})
	}
}

func TestValidateResponseIsStrict(t *testing.T) {
	candidates := []Candidate{{Path: ".config/tool/config.json"}}
	valid := Response{Results: []Result{{Path: candidates[0].Path, Decision: Portable, Confidence: .9, ReasonCode: "tool_config"}}}
	if err := validateResponse(valid, candidates); err != nil {
		t.Fatal(err)
	}
	valid.Results[0].Decision = "copy_everything"
	if err := validateResponse(valid, candidates); err == nil {
		t.Fatal("invalid decision was accepted")
	}
}
