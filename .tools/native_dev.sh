#!/bin/bash
# Run the dev server natively (no Docker) with ENV=DEVELOPMENT
cd "$(dirname "$0")/.." || exit 1

mkdir -p data

export DATABASE_URL="sqlite:///$(pwd)/data/kv.db"
export PORT="3000"
export ENV="DEVELOPMENT"
export SQLX_OFFLINE="true"

exec cargo run
