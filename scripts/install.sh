#!/usr/bin/env bash
# agssh installer: patch the live persist-ssh skill script with the agssh
# execute() extension, then symlink the plugin and CLI into place.
# Idempotent: safe to run more than once.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$HOME/.hermes/skills/devops/persistent-ssh/scripts/persist-ssh.py"
PATCH_FILE="$REPO/patches/persist-ssh-execute.patch"
REJ=/tmp/persist-ssh-patch.rej

patched=no
if grep -q "^def execute(" "$SKILL" 2>/dev/null; then
    echo "persist-ssh.py: already patched"
else
    if patch --backup-if-mismatch -r "$REJ" "$SKILL" < "$PATCH_FILE"; then
        patched=yes
    else
        echo "ERROR: patch failed; rejects saved to $REJ" >&2
        exit 1
    fi
fi

mkdir -p "$HOME/.hermes/plugins"
ln -sfn "$REPO/plugin/agssh" "$HOME/.hermes/plugins/agssh"

mkdir -p "$HOME/bin"
ln -sfn "$REPO/bin/agssh" "$HOME/bin/agssh"

echo
echo "agssh install summary:"
echo "  persist-ssh.py : $([ "$patched" = yes ] && echo patched || echo already patched)"
echo "  plugin link    : $HOME/.hermes/plugins/agssh -> $REPO/plugin/agssh"
echo "  cli link       : $HOME/bin/agssh -> $REPO/bin/agssh"
echo "tools appear on the next session"
