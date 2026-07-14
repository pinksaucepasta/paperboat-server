package configsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type classificationClient struct {
	endpoint, projectID, machineID, credential, journalPath string
	http                                                    *http.Client
}

type classificationCandidate struct {
	Path            string                  `json:"path"`
	FileType        string                  `json:"file_type"`
	Size            int64                   `json:"size"`
	ChangeFrequency string                  `json:"change_frequency"`
	LocationClass   string                  `json:"location_class"`
	Siblings        []classificationSibling `json:"siblings,omitempty"`
}
type classificationSibling struct {
	Name     string `json:"name"`
	FileType string `json:"file_type"`
}
type classificationResult struct {
	Path       string  `json:"path"`
	Decision   string  `json:"decision"`
	Confidence float64 `json:"confidence"`
	ReasonCode string  `json:"reason_code"`
	Pending    bool    `json:"pending"`
}
type classificationBatch struct {
	Results                                                   []classificationResult `json:"results"`
	Pending                                                   []PathSummary
	PolicyRevision, ModelRevision, ClassifierRevision, Health string
}

func newClassificationClient(journalPath, endpoint, projectID, machineID, credential string) *classificationClient {
	return &classificationClient{endpoint: endpoint, projectID: projectID, machineID: machineID, credential: credential, journalPath: journalPath, http: &http.Client{Timeout: 20 * time.Second}}
}

func (c *classificationClient) classify(ctx context.Context, local snapshot, changed []string) (classificationBatch, error) {
	batch := classificationBatch{Health: "healthy"}
	pending := c.readJournal()
	candidates := make(map[string]classificationCandidate, len(pending)+len(changed))
	for _, candidate := range pending {
		candidates[candidate.Path] = candidate
	}
	for _, rel := range changed {
		if deterministicPortable(rel) {
			batch.Results = append(batch.Results, classificationResult{Path: rel, Decision: "portable", Confidence: 1, ReasonCode: "vm_catalog"})
			delete(candidates, rel)
			continue
		}
		state, exists := local.Files[rel]
		if !exists {
			batch.Results = append(batch.Results, classificationResult{Path: rel, Decision: "portable", Confidence: 1, ReasonCode: "managed_deletion"})
			delete(candidates, rel)
			continue
		}
		fileType := "file"
		if state.Mode&os.ModeSymlink != 0 {
			fileType = "symlink"
		}
		candidates[rel] = classificationCandidate{Path: rel, FileType: fileType, Size: state.Bytes, ChangeFrequency: "changed", LocationClass: locationClass(rel), Siblings: siblingMetadata(local, rel)}
	}
	if len(candidates) == 0 {
		_ = c.writeJournal(nil)
		return batch, nil
	}
	values := make([]classificationCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		values = append(values, candidate)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Path < values[j].Path })
	if c.endpoint == "" || c.credential == "" {
		batch.Health = "unavailable"
		return c.pendingBatch(batch, values, "provider_unavailable")
	}
	payload, _ := json.Marshal(map[string]any{"project_id": c.projectID, "machine_id": c.machineID, "candidates": values})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return batch, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.credential)
	res, err := c.http.Do(req)
	if err != nil {
		batch.Health = "unavailable"
		return c.pendingBatch(batch, values, "provider_unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		batch.Health = "unavailable"
		return c.pendingBatch(batch, values, "provider_unavailable")
	}
	var envelope struct {
		Data struct {
			Results            []classificationResult `json:"results"`
			PolicyRevision     string                 `json:"policy_revision"`
			ModelRevision      string                 `json:"model_revision"`
			ClassifierRevision string                 `json:"classifier_revision"`
			Health             string                 `json:"health"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return batch, errors.New("classification response is invalid")
	}
	batch.Results = append(batch.Results, envelope.Data.Results...)
	batch.PolicyRevision = envelope.Data.PolicyRevision
	batch.ModelRevision = envelope.Data.ModelRevision
	batch.ClassifierRevision = envelope.Data.ClassifierRevision
	batch.Health = envelope.Data.Health
	still := make([]classificationCandidate, 0)
	for i, result := range envelope.Data.Results {
		if result.Pending || result.Decision == "uncertain" {
			batch.Pending = append(batch.Pending, PathSummary{Path: result.Path, Reason: result.ReasonCode})
			if i < len(values) {
				still = append(still, values[i])
			}
		}
	}
	if err := c.writeJournal(still); err != nil {
		return batch, err
	}
	return batch, nil
}

func (c *classificationClient) pendingBatch(batch classificationBatch, values []classificationCandidate, reason string) (classificationBatch, error) {
	for _, candidate := range values {
		batch.Results = append(batch.Results, classificationResult{Path: candidate.Path, Decision: "uncertain", ReasonCode: reason, Pending: true})
		batch.Pending = append(batch.Pending, PathSummary{Path: candidate.Path, Bytes: candidate.Size, Reason: reason})
	}
	return batch, c.writeJournal(values)
}
func (c *classificationClient) readJournal() []classificationCandidate {
	b, err := os.ReadFile(c.journalPath)
	if err != nil {
		return nil
	}
	var values []classificationCandidate
	if json.Unmarshal(b, &values) != nil {
		return nil
	}
	return values
}
func (c *classificationClient) writeJournal(values []classificationCandidate) error {
	if err := os.MkdirAll(filepath.Dir(c.journalPath), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(values)
	tmp := c.journalPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.journalPath)
}
func deterministicPortable(rel string) bool {
	if strings.HasPrefix(rel, ".paperboat-conflicts/") {
		return true
	}
	switch rel {
	case ".claude/.credentials.json", ".claude.json", ".codex/auth.json", ".config/opencode/auth.json", ".local/share/opencode/auth.json", ".npmrc", ".config/npm/npmrc":
		return true
	}
	return strings.HasSuffix(rel, "/settings.json") || strings.HasSuffix(rel, "/config.toml")
}
func locationClass(rel string) string {
	switch {
	case strings.HasPrefix(rel, ".config/"):
		return "xdg_config"
	case strings.HasPrefix(rel, ".local/share/"):
		return "xdg_data"
	case strings.HasPrefix(rel, ".local/state/"):
		return "xdg_state"
	case strings.HasPrefix(rel, ".cache/"):
		return "xdg_cache"
	default:
		return "home"
	}
}
func siblingMetadata(local snapshot, rel string) []classificationSibling {
	dir := path.Dir(rel)
	out := make([]classificationSibling, 0, 8)
	for candidate, state := range local.Files {
		if path.Dir(candidate) != dir || candidate == rel {
			continue
		}
		kind := "file"
		if state.Mode&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		out = append(out, classificationSibling{Name: path.Base(candidate), FileType: kind})
		if len(out) == 8 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
