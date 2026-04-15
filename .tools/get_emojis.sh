#!/usr/bin/env sh
# Downloads the full emoji dataset and writes a filtered [{e, n}] JSON array.
# Usage: .tools/get_emojis.sh OUTPUT_PATH
#
# Filters out:
#   - ZWJ sequences (family/couple combos) — codes contain 200D
#   - Skin-tone variants — subgroup contains "skin-tone"
#   - Flags — group is "Flags"
#   - Component entries (skin tones, hair) — group is "Component"
set -e

OUTPUT="${1:?Usage: .tools/get_emojis.sh OUTPUT_PATH}"

echo "Downloading emoji data..."
curl -sL "https://unpkg.com/emoji.json/emoji.json" | jq '[
  .[] | select(
    (.codes | test("200D") | not) and
    (.subgroup | test("skin-tone") | not) and
    (.group != "Flags") and
    (.group != "Component")
  ) | {e: .char, n: .name}
]' > "$OUTPUT"

COUNT=$(jq 'length' "$OUTPUT")
echo "Wrote $COUNT emojis to $OUTPUT"
