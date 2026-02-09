#!/usr/bin/env bash
# merge-version.sh — Merges a plugin version fragment into the registry index.
# Usage: merge-version.sh <version-entry.json> <index.json>
set -euo pipefail

FRAGMENT="$1"
INDEX="$2"

if [ ! -f "$FRAGMENT" ]; then
  echo "error: fragment file not found: $FRAGMENT" >&2
  exit 1
fi

if [ ! -f "$INDEX" ]; then
  echo "error: index file not found: $INDEX" >&2
  exit 1
fi

# Use jq to merge the version entry into the index.
# If the plugin already exists, append the version; otherwise add a new entry.
PLUGIN_NAME=$(jq -r '.name' "$FRAGMENT")
VERSION=$(jq -r '.version' "$FRAGMENT")

EXISTING=$(jq --arg name "$PLUGIN_NAME" '.plugins[] | select(.name == $name)' "$INDEX")

if [ -z "$EXISTING" ]; then
  # New plugin — create entry.
  jq --slurpfile frag "$FRAGMENT" \
    '.plugins += [{
      name: $frag[0].name,
      description: ($frag[0].description // ""),
      track: ($frag[0].track // ""),
      tags: ($frag[0].tags // []),
      versions: [{
        version: $frag[0].version,
        api_version: ($frag[0].api_version // "v1"),
        published_at: $frag[0].published_at,
        digest: ($frag[0].digest // ""),
        risk_class: ($frag[0].risk_class // "passive"),
        artifacts: ($frag[0].artifacts // [])
      }]
    }] | .generated_at = (now | todate)' "$INDEX" > "${INDEX}.tmp"
else
  # Existing plugin — append version.
  jq --slurpfile frag "$FRAGMENT" --arg name "$PLUGIN_NAME" \
    '(.plugins[] | select(.name == $name)).versions += [{
      version: $frag[0].version,
      api_version: ($frag[0].api_version // "v1"),
      published_at: $frag[0].published_at,
      digest: ($frag[0].digest // ""),
      risk_class: ($frag[0].risk_class // "passive"),
      artifacts: ($frag[0].artifacts // [])
    }] | .generated_at = (now | todate)' "$INDEX" > "${INDEX}.tmp"
fi

mv "${INDEX}.tmp" "$INDEX"
echo "Merged ${PLUGIN_NAME}@${VERSION} into index"
