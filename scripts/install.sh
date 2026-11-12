#!/usr/bin/env bash
# agssh local installer: symlink the plugin and CLI into place.
#
# The normal install path is `hermes plugins install mosesman831/agssh`.
# This script is for working from a clone. It does NOT touch any other
# skill by default; patching the legacy persist-ssh skill script is opt-in
# via --patch-persist-ssh, and it backs the file up first.
#
# Idempotent: safe to run more than once.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PATCH_SKILL=no
for arg in "$@"; do
    case "$arg" in
        --patch-persist-ssh) PATCH_SKILL=yes ;;
        -h|--help)
            echo "usage: scripts/install.sh [--patch-persist-ssh]"
            echo "  --patch-persist-ssh  also patch the legacy persist-ssh skill"
            echo "                       script (opt-in, backup written first)"
            exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

mkdir -p "$HOME/.hermes/plugins"
ln -sfn "$REPO/plugin/agssh" "$HOME/.hermes/plugins/agssh"

mkdir -p "$HOME/bin"
ln -sfn "$REPO/bin/agssh" "$HOME/bin/agssh"

skill_note="not touched (default)"
if [ "$PATCH_SKILL" = yes ]; then
    SKILL="$HOME/.hermes/skills/devops/persistent-ssh/scripts/persist-ssh.py"
    PATCH_FILE="$REPO/patches/persist-ssh-execute.patch"
    STATE_DIR="${HERMES_HOME:-$HOME/.hermes}/plugin-data/agssh"
    mkdir -p "$STATE_DIR"
    REJ="$STATE_DIR/persist-ssh-patch.rej"
    if [ ! -f "$SKILL" ]; then
        skill_note="skill not installed - skipped"
    elif grep -q "^def execute(" "$SKILL" 2>/dev/null; then
        skill_note="already patched"
    else
        cp -p "$SKILL" "$SKILL.agssh-orig"
        if patch --backup-if-mismatch -r "$REJ" "$SKILL" < "$PATCH_FILE"; then
            skill_note="patched (backup: $SKILL.agssh-orig)"
        else
            echo "ERROR: patch failed; rejects saved to $REJ" >&2
            exit 1
        fi
    fi
fi

echo
echo "agssh install summary:"
echo "  plugin link    : $HOME/.hermes/plugins/agssh -> $REPO/plugin/agssh"
echo "  cli link       : $HOME/bin/agssh -> $REPO/bin/agssh"
echo "  persist-ssh    : $skill_note"
echo "tools appear on the next session"