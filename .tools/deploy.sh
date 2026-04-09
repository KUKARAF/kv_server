#!/usr/bin/env bash
set -euo pipefail

REMOTE="rafa@bigboy"
REMOTE_DIR="/home/rafa/env/osmosis/kv"
POLL_INTERVAL=30

run_id=$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
echo "Watching run $run_id..."

while true; do
    read -r status conclusion < <(
        gh run view "$run_id" --json status,conclusion \
            --jq '[.status, .conclusion] | @tsv'
    )

    if [[ "$status" == "completed" ]]; then
        if [[ "$conclusion" == "success" ]]; then
            echo "Build succeeded. Deploying to $REMOTE..."
            ssh "$REMOTE" "cd $REMOTE_DIR && docker compose pull && docker compose up -d"
            echo "Done."
        else
            echo "Build finished with conclusion: $conclusion. Not deploying."
            exit 1
        fi
        break
    fi

    echo "  status=$status — waiting ${POLL_INTERVAL}s..."
    sleep "$POLL_INTERVAL"
done
