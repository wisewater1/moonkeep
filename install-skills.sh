#!/usr/bin/env bash
# Install the named-mode skills as personal skills so they're available in every project.
#
#   bash install-skills.sh            # copy each skill into ~/.claude/skills/
#   bash install-skills.sh --symlink  # symlink instead (repo edits stay live)
#
# After the first install, restart Claude Code once: a newly created top-level
# ~/.claude/skills/ directory is only watched after a restart.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.claude/skills"
DEST_DIR="${HOME}/.claude/skills"

mode="copy"
if [[ "${1:-}" == "--symlink" ]]; then
  mode="symlink"
elif [[ -n "${1:-}" ]]; then
  echo "Unknown option: $1" >&2
  echo "Usage: bash install-skills.sh [--symlink]" >&2
  exit 2
fi

if [[ ! -d "$SRC_DIR" ]]; then
  echo "Source skills directory not found: $SRC_DIR" >&2
  exit 1
fi

mkdir -p "$DEST_DIR"

count=0
for skill in "$SRC_DIR"/*/; do
  [[ -f "${skill}SKILL.md" ]] || continue   # only real skill dirs
  name="$(basename "$skill")"
  target="$DEST_DIR/$name"
  rm -rf "$target"
  if [[ "$mode" == "symlink" ]]; then
    ln -s "${skill%/}" "$target"
  else
    cp -R "${skill%/}" "$target"
  fi
  echo "  installed $name"
  count=$((count + 1))
done

echo ""
echo "Installed $count skills into $DEST_DIR ($mode)."
echo "Now restart Claude Code once so the skills directory is picked up, then type / to see them."
