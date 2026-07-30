#!/usr/bin/env bash
#
# Check every migration in a pull request against the production policy.
#
# `supasafe analyze` touches no database and writes nothing to the audit trail.
# It exits non-zero when a statement would be blocked, which is what makes it
# useful here.
#
#   ./check-migrations.sh origin/main
#
set -euo pipefail

BASE="${1:-origin/main}"
TARGET="${SUPASAFE_TARGET:-postgresql://postgres@db.example.supabase.co:5432/postgres}"

changed=$(git diff --name-only --diff-filter=ACM "$BASE"... -- '*.sql')

if [ -z "$changed" ]; then
  echo "No SQL changed."
  exit 0
fi

failed=0
for file in $changed; do
  echo "── $file"
  if ! supasafe analyze --file "$file" --target "$TARGET"; then
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  cat <<'EOF'

One or more statements would be blocked or held in production.

That is not automatically wrong. A migration that drops a column is supposed to
need a human. What it means is that somebody has to look at this before it
ships, and the output above says which statement and why.
EOF
  exit 1
fi

echo "Every statement would be allowed in production."
