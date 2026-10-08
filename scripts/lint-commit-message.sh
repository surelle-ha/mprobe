#!/bin/sh

set -eu

if [ "$#" -gt 0 ]; then
    subject=$(sed -n '1p' "$1")
else
    IFS= read -r subject || subject=''
fi

# Git creates these subjects itself when merging or reverting.
case "$subject" in
    "Merge "*|"Revert \""*) exit 0 ;;
esac

pattern='^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([a-z0-9][a-z0-9._/-]*\))?(!)?: .+'

if printf '%s\n' "$subject" | grep -Eq "$pattern"; then
    exit 0
fi

cat >&2 <<EOF
Invalid commit subject: $subject

Use Conventional Commits: type(scope): summary
Allowed types: build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test
Example: feat(probe): add SMTP preflight checks
EOF
exit 1
