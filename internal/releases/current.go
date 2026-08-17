package releases

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const CurrentSchemaV1 = "paperboat.release-current/v1"

type Current struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}

func ReadCurrent(directory string) (Current, error) {
	path := filepath.Join(directory, "current.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 4096 {
		return Current{}, errors.New("current release manifest is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return Current{}, err
	}
	defer file.Close()
	var current Current
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&current) != nil || decoder.Decode(&extra) != io.EOF || current.Schema != CurrentSchemaV1 || !validVersion(current.Version) {
		return Current{}, errors.New("current release manifest is invalid")
	}
	return current, nil
}

func Ready(directory string) error {
	current, err := ReadCurrent(directory)
	if err != nil {
		return err
	}
	for _, relative := range []string{"install", "tuf/metadata/root.json", "tuf/metadata/timestamp.json", "tuf/metadata/snapshot.json", "tuf/metadata/targets.json"} {
		info, err := os.Lstat(filepath.Join(directory, filepath.FromSlash(relative)))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 {
			return errors.New("release bundle is incomplete")
		}
	}
	body, err := os.ReadFile(filepath.Join(directory, "tuf", "metadata", "targets.json"))
	if err != nil || len(body) > 512<<10 {
		return errors.New("release targets metadata is unavailable")
	}
	var metadata struct {
		Signed struct {
			Targets map[string]struct {
				Length int64             `json:"length"`
				Hashes map[string]string `json:"hashes"`
				Custom json.RawMessage   `json:"custom"`
			} `json:"targets"`
		} `json:"signed"`
	}
	if json.Unmarshal(body, &metadata) != nil {
		return errors.New("release targets metadata is invalid")
	}
	for _, name := range []string{"pb-darwin-amd64", "pb-darwin-arm64", "pb-linux-amd64", "pb-linux-arm64"} {
		target, ok := metadata.Signed.Targets[name]
		digest := target.Hashes["sha256"]
		var custom struct {
			Version string `json:"version"`
		}
		if !ok || target.Length < 1 || len(digest) != 64 || json.Unmarshal(target.Custom, &custom) != nil || custom.Version != current.Version {
			return errors.New("release target metadata is incomplete")
		}
		targetPath := filepath.Join(directory, "tuf", "targets", digest+"."+name)
		targetInfo, statErr := os.Lstat(targetPath)
		if statErr != nil || !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("release target is unavailable or corrupt")
		}
		targetBody, readErr := os.ReadFile(targetPath)
		actual := sha256.Sum256(targetBody)
		if readErr != nil || int64(len(targetBody)) != target.Length || !strings.EqualFold(digest, fmt.Sprintf("%x", actual)) {
			return errors.New("release target is unavailable or corrupt")
		}
	}
	return nil
}

func validVersion(version string) bool {
	if version == "" || len(version) > 64 || strings.ContainsAny(version, "/\\\x00\r\n") {
		return false
	}
	for _, character := range version {
		if (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && !strings.ContainsRune("._-", character) {
			return false
		}
	}
	return true
}
