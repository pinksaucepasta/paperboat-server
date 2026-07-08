#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PAPERBOAT_GITHUB_CONFIG_TOKEN="github-token-secret"

github_password="$("$root/bin/paperboat-git-askpass" "Password for 'https://github.com/paperboat/config.git':")"
if [ "$github_password" != "github-token-secret" ]; then
  printf 'expected github token for github.com prompt\n' >&2
  exit 1
fi

evil_password="$("$root/bin/paperboat-git-askpass" "Password for 'https://evil.example/repo.git':")"
if [ -n "$evil_password" ]; then
  printf 'askpass returned token for disallowed host\n' >&2
  exit 1
fi

export PAPERBOAT_GITHUB_TOKEN_ALLOWED_HOSTS="github.com,github.enterprise.test"
enterprise_password="$("$root/bin/paperboat-git-askpass" "Password for 'https://github.enterprise.test/org/repo.git':")"
if [ "$enterprise_password" != "github-token-secret" ]; then
  printf 'expected github token for configured enterprise host\n' >&2
  exit 1
fi

unset PAPERBOAT_GITHUB_CONFIG_TOKEN
export PAPERBOAT_GITHUB_TOKEN_ENV="PAPERBOAT_CUSTOM_GITHUB_TOKEN"
export PAPERBOAT_CUSTOM_GITHUB_TOKEN="custom-github-token"
custom_password="$("$root/bin/paperboat-git-askpass" "Password for 'https://github.com/paperboat/config.git':")"
if [ "$custom_password" != "custom-github-token" ]; then
  printf 'expected token from configured github token env\n' >&2
  exit 1
fi
