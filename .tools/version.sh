#!/bin/bash
# Outputs the current version as major.minor.shortsha
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

BASE=$(cat VERSION | tr -d '[:space:]')
SHORT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")
echo "$BASE.$SHORT_SHA"
