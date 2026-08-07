#!/bin/bash
# Runs on every push (via .build.yml). Reviews the diff since the last
# reviewed commit with `hermes` running the code-review skill. hermes writes
# its findings to good.md/ticket.md (plain file writes — this is the only
# thing it does that has any effect outside its own working directory) and
# this wrapper script, never hermes itself, is the only thing that touches
# `hut`/todo.sr.ht credentials: it reads ticket.md and files a ticket only if
# non-empty. State (the last reviewed SHA) lives as a comment thread on a
# pinned ticket in the same tracker — see #STATE_TICKET.
set -euo pipefail

TRACKER="kv_manager-ai-review"
STATE_TICKET=1
MODEL="minimax/minimax-m3"

HUT_CONFIG="$HOME/.hut-ai-review-config"
cat > "$HUT_CONFIG" <<EOF
instance "sourcehut" {
	origin "sr.ht"
	access-token-cmd cat $HOME/.secrets/todo_ticket_token
}
EOF
hut() { command hut --config "$HUT_CONFIG" "$@"; }

LAST_SHA=$(hut todo ticket show -t "$TRACKER" "$STATE_TICKET" \
  | grep -o 'last-reviewed-sha=[0-9a-f]*' | tail -1 | cut -d= -f2 || true)

if [ -z "$LAST_SHA" ]; then
  echo "no last-reviewed-sha found on state ticket #$STATE_TICKET — aborting" >&2
  exit 1
fi

CURRENT_SHA=$(git rev-parse HEAD)

if [ "$LAST_SHA" = "$CURRENT_SHA" ]; then
  echo "nothing new since last review ($CURRENT_SHA)"
  exit 0
fi

if ! git cat-file -e "$LAST_SHA" 2>/dev/null; then
  echo "last-reviewed-sha $LAST_SHA not found in this checkout — reviewing only the tip commit instead" >&2
  LAST_SHA=$(git rev-parse "$CURRENT_SHA^")
fi

DIFF=$(git diff "$LAST_SHA".."$CURRENT_SHA" -- . ':(exclude).builds')

REVIEW_COMPLETED=1

if [ -z "$DIFF" ]; then
  echo "empty diff between $LAST_SHA and $CURRENT_SHA — nothing to review"
else
  export OPENROUTER_API_KEY
  OPENROUTER_API_KEY="$(cat "$HOME/.secrets/openrouter_api_key")"

  mkdir -p "$HOME/.hermes/skills"
  cp "$(dirname "$0")/code-review-skill.md" "$HOME/.hermes/skills/code-review.md"

  rm -f good.md ticket.md

  PROMPT_FILE=$(mktemp)
  {
    echo "/code-review"
    echo
    echo "Commit range $LAST_SHA..$CURRENT_SHA:"
    echo
    echo "$DIFF"
  } > "$PROMPT_FILE"

  export PATH="$HOME/.hermes/hermes-agent/venv/bin:$PATH"
  timeout 300 hermes chat -q "$(cat "$PROMPT_FILE")" \
    --provider openrouter --model "$MODEL" \
    --yolo --toolsets file \
    </dev/null || echo "hermes exited non-zero — checking for a ticket.md anyway" >&2

  rm -f "$PROMPT_FILE"

  # ticket.md's *existence* (not just non-emptiness) is the "review actually
  # completed" signal — the skill is instructed to always write it, even
  # empty, as its last action. No file at all means hermes crashed/timed out
  # partway through, so we must not advance state (that commit needs a retry
  # on the next push, not to be silently marked reviewed).
  if [ -e ticket.md ]; then
    if [ -s ticket.md ]; then
      hut todo ticket create -t "$TRACKER" < ticket.md
    else
      echo "ticket.md empty — no findings this run"
    fi
  else
    echo "hermes did not write ticket.md — review did not complete for $CURRENT_SHA; not advancing state" >&2
    echo "review failed to complete for commit $CURRENT_SHA (hermes did not write ticket.md) — will retry on next push" \
      | hut todo ticket comment -t "$TRACKER" "$STATE_TICKET"
    REVIEW_COMPLETED=0
  fi

  rm -f good.md ticket.md
fi

if [ "$REVIEW_COMPLETED" = "1" ]; then
  echo "state: last-reviewed-sha=$CURRENT_SHA" | hut todo ticket comment -t "$TRACKER" "$STATE_TICKET"
else
  exit 1
fi
