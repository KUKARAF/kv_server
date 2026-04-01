#!/bin/bash
# Run the test suite
cd "$(dirname "$0")/.." || exit 1
SQLX_OFFLINE=true exec cargo test "$@"
