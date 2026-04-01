#!/bin/bash
# Start production stack (pulls image from GHCR)
cd "$(dirname "$0")/.." || exit 1
exec podman compose -f docker-compose.yaml up
