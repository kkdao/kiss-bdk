#!/bin/sh
# Install the local publication checks after cloning.
set -eu
cd "$(dirname "$0")/.."
PYTHONDONTWRITEBYTECODE=1 python3 tools/hooks/test_publication_guard.py
DEST=$(git rev-parse --git-path hooks)
mkdir -p "$DEST"
for h in commit-msg pre-push publication_guard.py; do
    cp "tools/hooks/$h" "$DEST/$h"
    chmod +x "$DEST/$h"
    echo "installed: $DEST/$h"
done
