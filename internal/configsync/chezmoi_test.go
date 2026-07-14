package configsync

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateChezmoiSourceTreeRejectsExecutableSources(t *testing.T) {
	for _, name := range []string{"run_once_setup.sh", "modify_dot_zshrc", "external_fonts.toml", "encrypted_dot_config.tmpl", "private_executable_dot_tool"} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, name), []byte("unsafe"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateChezmoiSourceTree(root); err == nil {
			t.Fatalf("unsafe source %q was accepted", name)
		}
	}
}

func TestValidateChezmoiSourceTreeAcceptsEncryptedLiteralState(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"encrypted_dot_claude.json.age", "private_encrypted_dot_codex", "dot_config"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("age-encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateChezmoiSourceTree(root); err != nil {
		t.Fatal(err)
	}
}
