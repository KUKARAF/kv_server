#!/bin/bash
# Start dev stack (builds locally with hot-reload)
cd "$(dirname "$0")/.." || exit 1
exec podman compose -f dev.docker-compose.yaml up --build
