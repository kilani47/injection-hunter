#!/usr/bin/env bash
# assets/fetch-assets.sh
#
# OPTIONAL, author-run script. Populates the victory-gif asset slot
# (static/img/victory/<node-id>.gif) described in assets/README.md.
#
# This script is NEVER run automatically by the build, Dockerfile, or CI,
# it ships with placeholder URLs only, and does nothing useful until you
# (the operator) edit the URL_* variables below to point at media you
# personally have the rights to use, or knowingly accept the residual risk
# of using per the root NOTICE file.
#
# Usage: ./assets/fetch-assets.sh
set -euo pipefail

DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/static/img/victory"
mkdir -p "$DEST_DIR"

# --------------------------------------------------------------------------
# Fill these in yourself. Leave a slot commented out / blank to skip it,
# templates/victory.html falls back to the original CSS burst animation for
# any node with no file present.
# --------------------------------------------------------------------------
declare -A URLS=(
  # [p1_1]="https://REPLACE-ME.example/gate-of-trust.gif"
  # [p1_2]="https://REPLACE-ME.example/recipe-vault.gif"
  # [p1_3]="https://REPLACE-ME.example/results-board.gif"
  # [p1_4]="https://REPLACE-ME.example/silent-room.gif"
  # [p1_5]="https://REPLACE-ME.example/medical-bay.gif"
  # [p2_2]="https://REPLACE-ME.example/sealed-floor.gif"
  # [p2_3]="https://REPLACE-ME.example/disguised-examiner.gif"
  # [p3_1]="https://REPLACE-ME.example/spell-card.gif"
  # [p3_2]="https://REPLACE-ME.example/cursed-card.gif"
  # [p4_1]="https://REPLACE-ME.example/records-room.gif"
  # [p4_2]="https://REPLACE-ME.example/archive-guardian.gif"
  # [p4_3]="https://REPLACE-ME.example/zodiac-breach.gif"
  # [p5_1]="https://REPLACE-ME.example/manipulators-firewall.gif"
  # [p5_2]="https://REPLACE-ME.example/blueprint-tampering.gif"
  # [p5_3]="https://REPLACE-ME.example/sealed-archives.gif"
  # [f1]="https://REPLACE-ME.example/trick-tower-final.gif"
  # [f2]="https://REPLACE-ME.example/chairman-election.gif"
)

if [ "${#URLS[@]}" -eq 0 ]; then
  echo "assets/fetch-assets.sh: no URLs configured, edit the URLS map in this" >&2
  echo "script with your own author-supplied links first. Nothing to do." >&2
  exit 0
fi

for node_id in "${!URLS[@]}"; do
  url="${URLS[$node_id]}"
  dest="${DEST_DIR}/${node_id}.gif"
  echo "Fetching ${node_id} <- ${url}"
  curl -fsSL "$url" -o "$dest"
done

echo "Done. Files written to ${DEST_DIR}"
