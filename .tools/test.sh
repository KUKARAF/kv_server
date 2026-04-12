#!/bin/bash
# Run the test suite
cd "$(dirname "$0")/.." || exit 1
PKG_CONFIG_PATH="/nix/store/fgm3pz8486ksh3f94629lpb7xjr2wjp7-openssl-3.6.0-dev/lib/pkgconfig" SQLX_OFFLINE=true exec cargo test "$@"
