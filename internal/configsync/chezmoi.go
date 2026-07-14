package configsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type chezmoiSource struct {
	binary       string
	configPath   string
	sourceDir    string
	destination  string
	identityPath string
	recipient    string
}

func newChezmoiSource(binary, runtimeDir, sourceDir, destination, identityPath, recipient string) (*chezmoiSource, error) {
	values := []string{binary, runtimeDir, sourceDir, destination, identityPath, recipient}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return nil, errors.New("chezmoi encryption configuration is incomplete")
		}
	}
	if !filepath.IsAbs(sourceDir) || !filepath.IsAbs(destination) || !filepath.IsAbs(identityPath) {
		return nil, errors.New("chezmoi paths must be absolute")
	}
	configPath := filepath.Join(runtimeDir, "config-sync", "chezmoi.toml")
	return &chezmoiSource{binary: binary, configPath: configPath, sourceDir: sourceDir, destination: destination, identityPath: identityPath, recipient: recipient}, nil
}

func (c *chezmoiSource) writeConfig() error {
	if info, err := os.Stat(c.identityPath); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("age identity must be a private regular file")
	}
	if err := os.MkdirAll(filepath.Dir(c.configPath), 0o700); err != nil {
		return err
	}
	var body bytes.Buffer
	fmt.Fprintf(&body, "sourceDir = %q\ndestDir = %q\nencryption = \"age\"\n\n[age]\nidentity = %q\nrecipient = %q\n", c.sourceDir, c.destination, c.identityPath, c.recipient)
	return os.WriteFile(c.configPath, body.Bytes(), 0o600)
}

func (c *chezmoiSource) addEncrypted(ctx context.Context, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	if err := c.writeConfig(); err != nil {
		return err
	}
	args := []string{"--config", c.configPath, "add", "--encrypt", "--"}
	for _, rel := range paths {
		if err := validatePattern(rel); err != nil {
			return err
		}
		args = append(args, filepath.Join(c.destination, filepath.FromSlash(rel)))
	}
	return runChezmoi(ctx, c.binary, args...)
}

func (c *chezmoiSource) forget(ctx context.Context, rel string) error {
	if err := validatePattern(rel); err != nil {
		return err
	}
	if err := c.writeConfig(); err != nil {
		return err
	}
	return runChezmoi(ctx, c.binary, "--config", c.configPath, "forget", "--", filepath.Join(c.destination, filepath.FromSlash(rel)))
}

func (c *chezmoiSource) applyRestricted(ctx context.Context) error {
	if err := validateChezmoiSourceTree(c.sourceDir); err != nil {
		return err
	}
	if err := c.writeConfig(); err != nil {
		return err
	}
	return runChezmoi(ctx, c.binary, "--config", c.configPath, "apply", "--force", "--no-tty")
}

func runChezmoi(ctx context.Context, binary string, args ...string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "CHEZMOI_NO_PAGER=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chezmoi failed: %w: %s", err, sanitizeMessage(string(output)))
	}
	return nil
}

func validateChezmoiSourceTree(root string) error {
	return filepath.WalkDir(root, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, full)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" || strings.HasPrefix(rel, ".git/") || rel == ".paperboat" || strings.HasPrefix(rel, ".paperboat/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".tmpl") {
			return fmt.Errorf("unsafe chezmoi template source %q", rel)
		}
		for _, prefix := range []string{"run_", "run_once_", "run_onchange_", "modify_", "external_", "remove_", "create_", "exact_", "executable_"} {
			if strings.HasPrefix(name, prefix) || strings.Contains(name, "_"+prefix) {
				return fmt.Errorf("unsafe chezmoi source attribute in %q", rel)
			}
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source tree symlink is not allowed at %q", rel)
		}
		return nil
	})
}

type encryptedRepositoryFormat struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KeyVersion int    `json:"key_version"`
	Recipient  string `json:"recipient"`
}

func readEncryptedRepositoryFormat(root string) (encryptedRepositoryFormat, error) {
	marker := filepath.Join(root, ".paperboat", "format.json")
	b, err := os.ReadFile(marker)
	if err != nil {
		return encryptedRepositoryFormat{}, errors.New("encrypted config repository marker is missing")
	}
	var value encryptedRepositoryFormat
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.Format != "paperboat-chezmoi-age" || value.Version != 1 || strings.TrimSpace(value.Recipient) == "" {
		return encryptedRepositoryFormat{}, errors.New("encrypted config repository format is invalid")
	}
	return value, nil
}

func validateEncryptedRepository(root string) error {
	if _, err := readEncryptedRepositoryFormat(root); err != nil {
		return err
	}
	return validateChezmoiSourceTree(root)
}

func writeEncryptedRepositoryFormat(root string, value encryptedRepositoryFormat) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	marker := filepath.Join(root, ".paperboat", "format.json")
	tmp := marker + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, marker)
}
