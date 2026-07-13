package configsyncpolicy

var mandatoryExcludes = []string{
	".git", "**/.git",
	".ssh", "**/.ssh", ".gnupg", "**/.gnupg", ".password-store",
	".aws", "**/.aws", ".azure", ".config/gcloud", ".kube", "**/.kube", ".oci",
	".config/doctl", ".config/linode-cli", ".config/heroku", ".config/fly", ".config/vercel/auth.json", ".config/netlify/config.json",
	".docker/config.json", ".config/containers/auth.json", ".git-credentials", "**/.git-credentials", ".netrc", "**/.netrc",
	".npmrc", "**/.npmrc", ".config/npm/npmrc", ".pypirc", "**/.pypirc", ".gem/credentials", ".cargo/credentials", ".cargo/credentials.toml",
	".config/gh/hosts.yml", ".config/hub", ".config/git/credentials", ".config/pypoetry/auth.toml", ".config/rclone/rclone.conf", ".terraform.d/credentials.tfrc.json",
	".config/glab-cli/config.yml", ".config/composer/auth.json", ".config/pip/pip.conf", ".config/uv/uv.toml", ".config/opencode/auth.json", ".local/share/opencode/auth.json",
	".claude/.credentials.json", ".claude/session-env", ".claude/projects", ".claude/shell-snapshots", ".claude/history.jsonl", ".claude/debug", ".claude/cache", ".claude/todos", ".claude.json",
	".codex/auth.json", ".codex/sessions", ".codex/archived_sessions", ".codex/history.jsonl", ".codex/log", ".codex/tmp", ".cursor/auth.json", ".cursor/sessions", ".mcp.json",
	".cache", "**/.cache", ".local/share/keyrings", ".local/share/Trash", ".local/state",
	".config/1Password", ".config/Bitwarden", ".config/google-chrome", ".config/chromium", ".mozilla",
	".vscode-server/data/User/globalStorage", ".config/Code/User/globalStorage", ".config/Cursor/User/globalStorage",
	".npm/_logs", ".pnpm-store", ".yarn/cache", ".bun/install/cache", "**/cache", "**/caches", "**/log", "**/logs", "**/tmp", "**/temp",
	".bash_history", ".bash_sessions", ".zsh_history", ".python_history", ".node_repl_history", ".lesshst", ".config/fish/fish_history", ".config/nushell/history.txt", "**/history", "**/history.*", "**/*_history",
	"**/credentials", "**/credentials.*", "**/auth.json", "**/auth.toml", "**/auth.yml", "**/auth.yaml", "**/secrets.json", "**/secrets.yml", "**/secrets.yaml",
	".env", ".env.*", "**/.env", "**/.env.*", "**/*.log", "**/*.tmp", "**/*~", "**/.DS_Store",
}

func MandatoryExcludes() []string {
	return append([]string{}, mandatoryExcludes...)
}
