package configsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const conflictMetadataName = "metadata.json"

type conflictMetadata struct {
	SchemaVersion int    `json:"schema_version"`
	Path          string `json:"path"`
	Reason        string `json:"reason"`
	Kind          string `json:"kind"`
	Bytes         int64  `json:"bytes,omitempty"`
	Target        string `json:"target,omitempty"`
}

func preserveConflict(repo, projectID, rel string, state fileState, exists bool, now time.Time) error {
	if err := validatePattern(rel); err != nil {
		return err
	}
	projectRoot := filepath.Join(repo, ".paperboat", "conflicts", conflictProjectComponent(projectID))
	if err := os.MkdirAll(projectRoot, 0o700); err != nil {
		return fmt.Errorf("create conflict root: %w", err)
	}
	temporary, err := os.MkdirTemp(projectRoot, ".pending-")
	if err != nil {
		return fmt.Errorf("create conflict staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()

	metadata := conflictMetadata{SchemaVersion: 1, Path: rel, Reason: "concurrent_update", Kind: "deleted"}
	if exists {
		metadata.Bytes = state.Bytes
		if state.Mode&os.ModeSymlink != 0 {
			metadata.Kind = "symlink"
			metadata.Target = state.Target
		} else {
			metadata.Kind = "file"
			source := filepath.Join(repo, filepath.FromSlash(rel))
			if err := copyStatePath(source, filepath.Join(temporary, "content"), temporary, rel, state); err != nil {
				return fmt.Errorf("copy conflict content: %w", err)
			}
		}
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(temporary, conflictMetadataName), encoded, 0o600); err != nil {
		return fmt.Errorf("write conflict metadata: %w", err)
	}
	final := filepath.Join(projectRoot, conflictArtifactComponent(rel, now))
	if err := os.Rename(temporary, final); err != nil {
		return fmt.Errorf("publish conflict artifact: %w", err)
	}
	committed = true
	return nil
}

func conflictSummaries(repo string) ([]PathSummary, error) {
	root := filepath.Join(repo, ".paperboat", "conflicts")
	items := make([]PathSummary, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != conflictMetadataName {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("conflict metadata is not a regular file")
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var metadata conflictMetadata
		if err := json.Unmarshal(encoded, &metadata); err != nil {
			return fmt.Errorf("parse conflict metadata: %w", err)
		}
		if metadata.SchemaVersion != 1 || metadata.Reason != "concurrent_update" || (metadata.Kind != "file" && metadata.Kind != "symlink" && metadata.Kind != "deleted") {
			return errors.New("invalid conflict metadata")
		}
		item := PathSummary{Path: metadata.Path, Bytes: metadata.Bytes, Reason: metadata.Reason}
		if err := normalizeSummary(&item); err != nil {
			return err
		}
		items = append(items, item)
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return items, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read conflict artifacts: %w", err)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Path == items[j].Path {
			return items[i].Bytes < items[j].Bytes
		}
		return items[i].Path < items[j].Path
	})
	return uniqueSummaries(items), nil
}

func conflictProjectComponent(projectID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(projectID)))
	return "project-" + hex.EncodeToString(sum[:8])
}

func conflictArtifactComponent(rel string, now time.Time) string {
	sum := sha256.Sum256([]byte(rel))
	return now.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(sum[:8])
}

func uniqueSummaries(values []PathSummary) []PathSummary {
	seen := make(map[string]struct{}, len(values))
	out := make([]PathSummary, 0, len(values))
	for _, value := range values {
		key := value.Path + "\x00" + value.Reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
